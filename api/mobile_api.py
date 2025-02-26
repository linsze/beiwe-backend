import calendar
import json
import plistlib
import time
from datetime import datetime, timedelta

from django.core.files.base import ContentFile
from django.core.files.uploadedfile import InMemoryUploadedFile, TemporaryUploadedFile
from django.http.response import HttpResponse
from django.utils import timezone

from authentication.participant_authentication import (authenticate_participant,
    authenticate_participant_registration, minimal_validation)
from config.settings import UPLOAD_LOGGING_ENABLED
from constants.celery_constants import ANDROID_FIREBASE_CREDENTIALS, IOS_FIREBASE_CREDENTIALS
from constants.message_strings import (DEVICE_CHECKED_IN, DEVICE_IDENTIFIERS_HEADER,
    INVALID_EXTENSION_ERROR, NO_FILE_ERROR, UNKNOWN_ERROR)
from database.data_access_models import FileToProcess
from database.schedule_models import ScheduledEvent
from database.survey_models import Survey
from database.system_models import FileAsText
from database.user_models_participant import Participant
from libs.encryption import (DecryptionKeyInvalidError, DeviceDataDecryptor,
    IosDecryptionKeyDuplicateError, IosDecryptionKeyNotFoundError, RemoteDeleteFileScenario)
from libs.http_utils import determine_os_api
from libs.internal_types import ParticipantRequest, ScheduledEventQuerySet
from libs.participant_file_uploads import (upload_and_create_file_to_process_and_log,
    upload_problem_file)
from libs.s3 import get_client_public_key_string, s3_upload
from libs.schedules import (decompose_datetime_to_timings, export_weekly_survey_timings,
    repopulate_all_survey_scheduled_events)
from libs.sentry import make_sentry_client, SentryTypes
from middleware.abort_middleware import abort


def log(*args, **kwargs):
    if UPLOAD_LOGGING_ENABLED:
        print(*args, **kwargs)


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
    request.session_participant.update_only(last_upload=timezone.now())
    
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
        log(200, "participant unregistered.")
        return HttpResponse(status=200)
    
    # iOS can upload identically named files with different content (and missing decryption keys) so
    # we need to return a 400 to back off. The device can try again later when the extant FTP has
    # been processed. (ios files with bad decryption keys fail and don't create new FTPs.)
    if FileToProcess.test_file_path_exists(s3_file_location, participant.study.object_id):
        log("400, FileToProcess.test_file_path_exists")
        return HttpResponse(content="", status=400)
    
    # attempt to decrypt, some scenarios delete remote files even if decryption fails
    try:
        file_contents = get_uploaded_file(request)
        decryptor = DeviceDataDecryptor(s3_file_location, file_contents, participant)
    except RemoteDeleteFileScenario:
        log(200, "RemoteDeleteFileScenario")  # errors were unrecoverable, delete the file.
        return HttpResponse(status=200)
    
    except (DecryptionKeyInvalidError, IosDecryptionKeyNotFoundError, IosDecryptionKeyDuplicateError) as e:
        # IOS has a complex issue where it splits files into multiple segments, but the key is only
        # present on the first section. We stash those files and attempt to extract useful
        # information on the data processing server.
        upload_problem_file(file_contents, participant, s3_file_location, e)
        return HttpResponse(status=200)
    
    # if uploaded data actually exists, and has a valid extension
    if decryptor.decrypted_file and file_name and contains_valid_extension(file_name):
        return upload_and_create_file_to_process_and_log(s3_file_location, participant, decryptor)
    elif not decryptor.decrypted_file:
        # file was empty (probably unreachable code due to decryption architecture
        return HttpResponse(status=200)
    else:
        return make_upload_error_report(participant.patient_id, file_name)


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
        log("get_uploaded_file, file not present")
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
    log(400, error_message, "(upload error report)")
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
    Returns the encryption key for this patient/user. 
    
    We used to have a test of the device id to require the device could not be changed without
    contacting the study researcher/admin. It became impossible to maintain this as operating
    systems changed and blocked device-specific ids. There was a similar test for locking a user to
    an operating system type that was dropped. """
    request.session_participant.update_only(last_register_user=timezone.now())
    if (
        'patient_id' not in request.POST
        or 'phone_number' not in request.POST
        or 'device_id' not in request.POST
        or 'new_password' not in request.POST
    ):
        return HttpResponse(content="", status=400)
    
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
    
    if participant.unregistered:
        return abort(400)
    
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
        'device_settings': participant.study.device_settings.export(),
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
    request.session_participant.update_only(last_set_password=timezone.now())
    new_password = request.POST.get("new_password", None)
    if new_password is None:
        return HttpResponse(content="", status=400)
    request.session_participant.set_password(new_password)
    return HttpResponse(status=200)


################################################################################
########################## FILE NAME FUNCTIONALITY #############################
################################################################################

def convert_filename_to_datetime(file_name: str):
    # "file_name" has underscores, "s3_file_path" has slashes
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
def get_latest_device_settings(request: ParticipantRequest, OS_API=""):
    """ Extremely simple endpoint that returns the device settings for the study as a json string. 
    Endpoint is used by the app to periodically check for changes to the device settings. """
    request.session_participant.update_only(last_get_latest_device_settings=timezone.now())
    return HttpResponse(
        json.dumps(request.session_participant.study.device_settings.export())
    )


@determine_os_api
@authenticate_participant
def get_latest_surveys(request: ParticipantRequest, OS_API=""):
    """ This is the endpoint hit by the app to downwload the current survey and survey schedule 
    information.  The app's representation of surveys is of the current week. """
    # todo: document exactly how many days of survey info the ios and android apps use. determine any architectural differences
    
    # record that participant checked in.
    now = timezone.now()
    request.session_participant.update_only(last_get_latest_surveys=now)
    
    # if there was a "checkin_uuid" parameter, indicate participant and ScheduledEvent of checkin.
    checkin_uuid = request.POST.get("checkin_uuid", None)
    if checkin_uuid:
        schedule: ScheduledEvent = ScheduledEvent.objects.get(uuid=checkin_uuid)
        if request.session_participant.first_push_notification_checkin is None:
            request.session_participant.update(first_push_notification_checkin=now)
        schedule.update(checkin_time=now)
        schedule.archive(True, DEVICE_CHECKED_IN, now)
    
    survey_json_list = []
    survey: Survey
    for survey in request.session_participant.study.surveys.filter(deleted=False):
        # Exclude image surveys for the Android app to avoid crashing it
        if not (OS_API == "ANDROID" and survey.survey_type == "image_survey"):
            survey_json_list.append(format_survey_for_device(survey, request.session_participant))
    
    return HttpResponse(json.dumps(survey_json_list))

# TODO: move this stuff elsewhere.


def format_survey_for_device(survey: Survey, participant: Participant):
    """ Returns a dict with the values of the survey fields for download to the app """
    survey_dict = survey.as_unpacked_native_python(Survey.SURVEY_DEVICE_EXPORT_FIELDS)
    # Make the dict look like the old Mongolia-style dict that the frontend is expecting
    survey_dict['_id'] = survey_dict.pop('object_id')
    
    # weekly defines a list of 7 lists of ints or [[], [], [], [], [], [], []]
    survey_timings = export_weekly_survey_timings(survey)
    
    # While it seems complex to force arbitrary non-repeating weekly-style schedules into a
    # weekly-based representation time, it turns out we only need to observe some rules:
    # 1) When "now" becomes the time for a survey notification to appear, it will appear.
    # 2) When the survey time is removed from the weekly timings the notification will disappear.
    # 3) Time is 1 week long; keep the examined period of time less than 7 days to avoid corner cases.
    # So, bracket our view of absolute and relative surveys schedule events like this:
    now = survey.study.now()  # TODO: get participant device timezone
    now_date = now.date()
    the_past = \
        datetime.combine((now_date - timedelta(days=4)), datetime.min.time(), tzinfo=now.tzinfo)
    the_future = \
        datetime.combine((now_date + timedelta(days=3)), datetime.min.time(), tzinfo=now.tzinfo)
    
    # This query results in a moving window of that "snaps" based on the day at midnight. retains
    # notifications for 4 days, and gives the app 3 days of failing to check in until it is out of
    # sync with abosule and relative surveys.
    # (filter with __lt for the_future since we are "zeroing" to midnight, __gte for the_past.)
    query: ScheduledEventQuerySet = survey.scheduled_events.filter(
        scheduled_time__gte=the_past,
        scheduled_time__lt=the_future,
        participant=participant,
        # deleted=False,  # ALWAYS send it. Consider notifications broken.
    ).exclude(weekly_schedule__isnull=False)  # skip where attached weekly schedules are not null
    
    for schedule in query:
        # The date component is dropped, the representation is now 100% a weekly schedule
        # the correct timezone is the "canonical form", e.g. in the study timezone (and then in 
        # survey timings form as offset from start of day)
        day_index, seconds = decompose_datetime_to_timings(schedule.scheduled_time_in_canonical_form)
        survey_timings[day_index].append(seconds)
    
    # sort, deduplicate all days lists
    for i in range(len(survey_timings)):
        survey_timings[i] = sorted(set(survey_timings[i]))
    
    # TODO: include schedule event uuids so that we can have full survey state tracking in a v2
    #   endpoint where we actually send a real schedule with absolute representations of time
    #   instead of the moving window hack.
    
    survey_dict['timings'] = survey_timings
    survey_dict["name"] = survey.name
    return survey_dict
