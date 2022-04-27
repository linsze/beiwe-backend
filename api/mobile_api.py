import calendar
import json
import plistlib
import time
from datetime import datetime, timedelta

from django.core.exceptions import ValidationError
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import InMemoryUploadedFile, TemporaryUploadedFile
from django.db import IntegrityError
from django.http.response import HttpResponse
from django.utils import timezone

from authentication.participant_authentication import (authenticate_participant,
    authenticate_participant_registration, minimal_validation)
from config.settings import REPORT_DECRYPTION_KEY_ERRORS
from constants.celery_constants import ANDROID_FIREBASE_CREDENTIALS, IOS_FIREBASE_CREDENTIALS
from constants.message_strings import (DECRYPTION_KEY_ADDITIONAL_MESSAGE, DEVICE_IDENTIFIERS_HEADER,
    INVALID_EXTENSION_ERROR, NO_FILE_ERROR, S3_FILE_PATH_UNIQUE_CONSTRAINT_ERROR_1,
    S3_FILE_PATH_UNIQUE_CONSTRAINT_ERROR_2, UNKNOWN_ERROR)
from constants.participant_constants import IOS_API
from database.data_access_models import FileToProcess
from database.profiling_models import DecryptionKeyError, UploadTracking
from database.system_models import FileAsText
from database.user_models import Participant
from libs.encryption import (DecryptionKeyInvalidError, DeviceDataDecryptor,
    IosDecryptionKeyNotFoundError, RemoteDeleteFileScenario)
from libs.http_utils import determine_os_api
from libs.internal_types import ParticipantRequest
from libs.push_notification_helpers import repopulate_all_survey_scheduled_events
from libs.s3 import get_client_public_key_string, s3_retrieve, s3_upload, smart_s3_list_study_files
from libs.sentry import make_sentry_client, SentryTypes
from middleware.abort_middleware import abort


EARLIEST_POSSIBLE_IOS_RECOVERY = datetime(2022, 4, 11, 0, 0, 0, 0)

ALLOWED_EXTENSIONS = {'csv', 'json', 'mp4', "wav", 'txt', 'jpg'}

################################################################################
################################ UPLOADS #######################################
################################################################################

@determine_os_api
@minimal_validation
def upload(request: ParticipantRequest, OS_API=""):
    """ Entry point to upload all data to aws s3.
    - The Beiwe apps delete their copy of the uploaded file if it receives an html 200 response.
    - The API returns a 200 response when...
      - the file upload was successful.
      - the file received was empty.
      - the file could not decrypt. (numerous cases of this are covered and handled internally)
      - when there are problems with the file name.
    - The Beiwe apps skip the file and will try again later if they receive a 400 or 500 class error.
    We do this when:
      - the normal 400 error case where the post request parameters are invalid.
      - a specific cases involving duplicate uploads spaced closely in time.
      - a specific case involving a bug in the ios app where a file is split and  losing its 
      decryption key.
    Request:
      - line-by-line-encrypted file contents in parameter "file"
      - file name in parameter "file_name"  """
    
    # Handle these corner cases first because they requires no database input.
    file_name = request.POST.get("file_name", None)
    if (
        not file_name  # there must be a file name
        or file_name.startswith("rList")  # rList are randomly generated by android
        or file_name.startswith("PersistedInstallation")  # come from firebase.
        or not contains_valid_extension(file_name)  # generic junk file test
    ):
        return HttpResponse(status=200)
    
    s3_file_location = file_name.replace("_", "/")
    participant = request.session_participant
    
    if participant.unregistered:  # "Unregistered" participant uploads should delete their data.
        return HttpResponse(status=200)
    
    # iOS can upload identically named files with different content (and missing decryption keys) so
    # we need to return a 400 to back off. The device can try again later when the extant FTP has
    # been processed. (ios files with bad decryption keys fail and don't create new FTPs.)
    if FileToProcess.test_file_path_exists(s3_file_location, participant.study.object_id):
        return HttpResponse(status=400)
    
    # get_uploaded_file failure modes always aborts or errors
    try:
        decryptor = DeviceDataDecryptor(s3_file_location, get_uploaded_file(request), participant)
    except RemoteDeleteFileScenario:
        # this class of error occurs we delete the  file on the device
        return HttpResponse(status=200)
    
    except DecryptionKeyInvalidError:
        # when the decryption key is invalid the file is lost.  Nothing we can do.
        # record the event, send the device a 200 so it can clear out the file.
        if REPORT_DECRYPTION_KEY_ERRORS:
            tags = {
                "participant": participant.patient_id,
                "operating system": participant.os_type,
                "DecryptionKeyError id": str(DecryptionKeyError.objects.last().id),
                "file_name": file_name,
                "bug_report": DECRYPTION_KEY_ADDITIONAL_MESSAGE,
            }
            with make_sentry_client(SentryTypes.elastic_beanstalk, tags):
                raise
        # iOS has a bug where a file can get split, we can recover those files. (200 would delete)
        return abort(400) if OS_API == IOS_API else HttpResponse(status=200)  # NOQA:
    
    except IosDecryptionKeyNotFoundError:
        file_timestamp = convert_filename_to_datetime(file_name)
        if (file_timestamp < EARLIEST_POSSIBLE_IOS_RECOVERY 
            or file_timestamp < (datetime.now() - timedelta(days=21))):
            return HttpResponse(status=200)
        else:
            return abort(400)
    
    # if uploaded data actually exists, and has a valid extension
    if decryptor.decrypted_file and file_name and contains_valid_extension(file_name):
        return upload_and_log(s3_file_location, participant, decryptor)
    elif not decryptor.decrypted_file:
        # if the file turns out to be empty, delete it, we simply do not care.
        return HttpResponse(status=200)
    else:
        return make_upload_error_report(participant.patient_id, file_name)


def upload_and_log(
    s3_file_location: str, participant: Participant, decryptor: DeviceDataDecryptor
) -> HttpResponse:
    # test if the file exists on s3, handle ios duplicate file merge.
    if not smart_s3_list_study_files(s3_file_location, participant):
        s3_upload(s3_file_location, decryptor.decrypted_file, participant)
    elif decryptor.used_ios_decryption_key_cache:
        s3_upload(
            s3_file_location,
            b"\n".join([s3_retrieve(s3_file_location, participant), decryptor.decrypted_file]),
            participant,
        )
    else:
        raise NotImplementedError("true duplicate upload handling on os: {participant.os_type}")
    
    # race condition: multiple _concurrent_ uploads with same file path. Behavior without try-except
    # is correct, but we don't care about reporting it. Just send the device a 500 error so it skips
    # the file, the followup attempt receives 200 code and deletes the file.
    try:
        FileToProcess.append_file_for_processing(s3_file_location, participant)
    except (IntegrityError, ValidationError) as e:
        # there are two error cases that can occur here (race condition with 2 concurrent uploads)
        if (
            S3_FILE_PATH_UNIQUE_CONSTRAINT_ERROR_1 in str(e)
            or S3_FILE_PATH_UNIQUE_CONSTRAINT_ERROR_2 in str(e)
        ):
            # don't abort 500, we want to limit 500 errors on the ELB in production (uhg)
            print("backoff for duplicate race condition.")
            return abort(400)
    
    # record that an upload occurred
    UploadTracking.objects.create(
        file_path=s3_file_location,
        file_size=len(decryptor.decrypted_file),
        timestamp=timezone.now(),
        participant=participant,
    )
    return HttpResponse(status=200)


# FIXME: Device Testing. this function exists to handle some ancient behavior, it definitely has
#  details that can be removed, and an error case that can probably go too.
def get_uploaded_file(request: ParticipantRequest) -> bytes:
    # Slightly different values for iOS vs Android behavior.
    # Android sends the file data as standard form post parameter (request.POST)
    # iOS sends the file as a multipart upload (so ends up in request.FILES)
    if "file" in request.FILES:
        uploaded_file = request.FILES['file']  # ios
    elif "file" in request.POST:
        uploaded_file = request.POST['file']  # android
    else:
        return abort(400)  # no uploaded file, bad request.
    
    # okay for some reason we get different file-like types in different scenarios?
    if isinstance(uploaded_file, (ContentFile, InMemoryUploadedFile, TemporaryUploadedFile)):
        uploaded_file = uploaded_file.read()
    
    if isinstance(uploaded_file, str):
        uploaded_file = uploaded_file.encode()  # android
    elif isinstance(uploaded_file, bytes):
        pass  # nothing needs to happen (ios)
    else:
        raise TypeError(f"uploaded_file was a {type(uploaded_file)}")
    return uploaded_file


def make_upload_error_report(patient_id: str, file_name: str):
    """ Does the work of packaging up a useful error message. """
    error_message = "an upload has failed " + patient_id + ", " + file_name + ", "
    if not file_name:
        error_message += NO_FILE_ERROR
    elif file_name and not contains_valid_extension(file_name):
        error_message += INVALID_EXTENSION_ERROR
    else:
        error_message += UNKNOWN_ERROR
    
    tags = {"upload_error": "upload error", "user_id": patient_id}
    sentry_client = make_sentry_client(SentryTypes.elastic_beanstalk, tags)
    sentry_client.captureMessage(error_message)
    return abort(400)


################################################################################
############################## Registration ####################################
################################################################################

@determine_os_api
@authenticate_participant_registration
def register_user(request: ParticipantRequest, OS_API=""):
    """ Checks that the patient id has been granted, and that there is no device registered with
    that id.  If the patient id has no device registered it registers this device and logs the
    bluetooth mac address.
    Check the documentation in participant_authentication to ensure you have provided the proper credentials.
    Returns the encryption key for this patient/user. """
    
    if (
        'patient_id' not in request.POST
        or 'phone_number' not in request.POST
        or 'device_id' not in request.POST
        or 'new_password' not in request.POST
    ):
        return abort(400)
    
    # CASE: If the id and password combination do not match, the decorator returns a 403 error.
    # the following parameter values are required.
    patient_id = request.POST['patient_id']
    phone_number = request.POST['phone_number']
    device_id = request.POST['device_id']
    
    # These values may not be returned by earlier versions of the beiwe app
    device_os = request.POST.get('device_os', "none")
    os_version = request.POST.get('os_version', "none")
    product = request.POST.get("product", "none")
    brand = request.POST.get("brand", "none")
    hardware_id = request.POST.get("hardware_id", "none")
    manufacturer = request.POST.get("manufacturer", "none")
    model = request.POST.get("model", "none")
    beiwe_version = request.POST.get("beiwe_version", "none")
    
    # This value may not be returned by later versions of the beiwe app.
    mac_address = request.POST.get('bluetooth_id', "none")
    
    participant = request.session_participant
    if participant.device_id and participant.device_id != device_id:
        # CASE: this patient has a registered a device already and it does not match this device.
        #   They need to contact the study and unregister their their other device.  The device
        #   will receive a 405 error and should alert the user accordingly.
        # Provided a user does not completely reset their device (which resets the device's
        # unique identifier) they user CAN reregister an existing device, the unlock key they
        # need to enter to at registration is their old password.
        # KG: 405 is good for IOS and Android, no need to check OS_API
        return abort(405)
    
    # if participant.os_type and participant.os_type != OS_API:
    #     # CASE: this patient has registered, but the user was previously registered with a
    #     # different device type. To keep the CSV munging code sane and data consistent (don't
    #     # cross the iOS and Android data streams!) we disallow it.
    #     return abort(400)
    
    # At this point the device has been checked for validity and will be registered successfully.
    # Any errors after this point will be server errors and return 500 codes. the final return
    # will be the encryption key associated with this user.
    
    # Upload the user's various identifiers.
    unix_time = str(calendar.timegm(time.gmtime()))
    file_name = patient_id + '/identifiers_' + unix_time + ".csv"
    
    # Construct a manual csv of the device attributes
    file_contents = (DEVICE_IDENTIFIERS_HEADER + "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s" %
                     (patient_id, mac_address, phone_number, device_id, device_os,
                      os_version, product, brand, hardware_id, manufacturer, model,
                      beiwe_version)).encode()
    
    s3_upload(file_name, file_contents, participant)
    FileToProcess.append_file_for_processing(file_name, participant)
    
    # set up device.
    participant.device_id = device_id
    participant.os_type = OS_API
    participant.set_password(request.POST['new_password'])  # set password saves the model
    device_settings = participant.study.device_settings.as_unpacked_native_python()
    device_settings.pop('_id', None)
    
    # set up FCM files
    firebase_plist_data = None
    firebase_json_data = None
    if participant.os_type == 'IOS':
        ios_credentials = FileAsText.objects.filter(tag=IOS_FIREBASE_CREDENTIALS).first()
        if ios_credentials:
            firebase_plist_data = plistlib.loads(ios_credentials.text.encode())
    elif participant.os_type == 'ANDROID':
        android_credentials = FileAsText.objects.filter(tag=ANDROID_FIREBASE_CREDENTIALS).first()
        if android_credentials:
            firebase_json_data = json.loads(android_credentials.text)
    
    # ensure the survey schedules are updated for this participant.
    repopulate_all_survey_scheduled_events(participant.study, participant)
    
    return_obj = {
        'client_public_key': get_client_public_key_string(patient_id, participant.study.object_id),
        'device_settings': device_settings,
        'ios_plist': firebase_plist_data,
        'android_firebase_json': firebase_json_data,
        'study_name': participant.study.name,
        'study_id': participant.study.object_id,
    }
    return HttpResponse(json.dumps(return_obj))


################################################################################
############################### USER FUNCTIONS #################################
################################################################################


@determine_os_api
@authenticate_participant
def set_password(request: ParticipantRequest, OS_API=""):
    """ After authenticating a user, sets the new password and returns 200.
    Provide the new password in a parameter named "new_password"."""
    new_password = request.POST.get("new_password", None)
    if new_password is None:
        return abort(400)
    request.session_participant.set_password(new_password)
    return HttpResponse(status=200)


################################################################################
########################## FILE NAME FUNCTIONALITY #############################
################################################################################

def convert_filename_to_datetime(file_name: str):
    should_be_numbers = file_name.split("_")[-1][:-4]
    if not should_be_numbers.isnumeric():
        raise Exception(f"bad numbers in '{file_name}': {should_be_numbers}")
    
    if len(should_be_numbers) == 13:
        should_be_numbers = should_be_numbers[:-3]
    elif len(should_be_numbers) != 10:
        raise Exception(f"bad digit count in {file_name}: {should_be_numbers}")
    
    return datetime.utcfromtimestamp(int(should_be_numbers))


def grab_file_extension(file_name: str):
    """ grabs the chunk of text after the final period. """
    return file_name.rsplit('.', 1)[1]


def contains_valid_extension(file_name: str):
    """ Checks if string has a recognized file extension, this is not necessarily limited to 4 characters. """
    return '.' in file_name and grab_file_extension(file_name) in ALLOWED_EXTENSIONS


################################################################################
################################# DOWNLOAD #####################################
################################################################################


@determine_os_api
@authenticate_participant
def get_latest_surveys(request: ParticipantRequest, OS_API=""):
    survey_json_list = []
    for survey in request.session_participant.study.surveys.filter(deleted=False):
        # Exclude image surveys for the Android app to avoid crashing it
        if not (OS_API == "ANDROID" and survey.survey_type == "image_survey"):
            survey_json_list.append(survey.format_survey_for_study())
    return HttpResponse(json.dumps(survey_json_list))
