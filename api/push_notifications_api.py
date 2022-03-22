import json
from datetime import datetime

from django.contrib import messages
from django.core.exceptions import ValidationError
from django.http.response import HttpResponse
from django.shortcuts import get_object_or_404, redirect
from django.utils import timezone
from django.views.decorators.http import require_POST
from firebase_admin import messaging
from firebase_admin.exceptions import FirebaseError

from authentication.admin_authentication import authenticate_researcher_study_access
from authentication.participant_authentication import authenticate_participant
from constants.datetime_constants import API_TIME_FORMAT
from constants.participant_constants import ANDROID_API, IOS_API
from database.schedule_models import ArchivedEvent
from database.study_models import Study
from database.survey_models import Survey
from database.user_models import Participant, ParticipantFCMHistory
from libs.firebase_config import check_firebase_instance
from libs.internal_types import ParticipantRequest, ResearcherRequest
from libs.sentry import make_error_sentry, SentryTypes
from middleware.abort_middleware import abort


################################################################################
########################### NOTIFICATION FUNCTIONS #############################
################################################################################


# TODO: this function incorrectly resets the push_notification_unreachable_count on an unsuccessful
#   empty push notification.  There is also a race condition at play, and while the current
#   mechanism works there is inappropriate content within the try statement that obscures the source
#   of the validation error, which actually occurs at the get-or-create line resulting in the bug.
#  Probably use a transaction?
@require_POST
@authenticate_participant
def set_fcm_token(request: ParticipantRequest):
    """ Sets a participants Firebase Cloud Messaging (FCM) instance token, called whenever a new
    token is generated. Expects a patient_id and and fcm_token in the request body. """
    participant = request.session_participant
    token = request.POST.get('fcm_token', "")
    now = timezone.now()
    
    # force to unregistered on success, force every not-unregistered as unregistered.
    
    # need to get_or_create rather than catching DoesNotExist to handle if two set_fcm_token
    # requests are made with the same token one after another and one request.
    try:
        p, _ = ParticipantFCMHistory.objects.get_or_create(token=token, participant=participant)
        p.unregistered = None
        p.save()  # retain as save, we want last_updated to mutate
        ParticipantFCMHistory.objects.exclude(token=token).filter(
            participant=participant, unregistered=None
        ).update(unregistered=now, last_updated=now)
    # ValidationError happens when the app sends a blank token
    except ValidationError:
        ParticipantFCMHistory.objects.filter(
            participant=participant, unregistered=None
        ).update(unregistered=now, last_updated=now)
    
    participant.push_notification_unreachable_count = 0
    participant.save()
    return HttpResponse(status=204)


@require_POST
@authenticate_participant
def developer_send_test_notification(request: ParticipantRequest):
    """ Sends a push notification to the participant, used ONLY for testing.
    Expects a patient_id in the request body. """
    print(check_firebase_instance())
    message = messaging.Message(
        data={
            'type': 'fake',
            'content': 'hello good sir',
        },
        token=request.session_participant.get_fcm_token().token,
    )
    response = messaging.send(message)
    print('Successfully sent notification message:', response)
    return HttpResponse(status=204)


@require_POST
@authenticate_participant
def developer_send_survey_notification(request: ParticipantRequest):
    """ Sends a push notification to the participant with survey data, used ONLY for testing
    Expects a patient_id in the request body """
    participant = request.session_participant
    survey_ids = list(
        participant.study.surveys.filter(deleted=False).exclude(survey_type="image_survey")
            .values_list("object_id", flat=True)[:4]
    )
    message = messaging.Message(
        data={
            'type': 'survey',
            'survey_ids': json.dumps(survey_ids),
            'sent_time': datetime.now().strftime(API_TIME_FORMAT),
        },
        token=participant.get_fcm_token().token,
    )
    response = messaging.send(message)
    print('Successfully sent survey message:', response)
    return HttpResponse(status=204)


@require_POST
@authenticate_researcher_study_access
def resend_push_notification(request: ResearcherRequest, study_id: int, patient_id: str):
    # 400 error if survey_id is not present
    survey_id = request.POST.get("survey_id", None)
    if not survey_id:
        return abort(400)
    
    # oodles of setup, 404 cases for db queries, the redirect action...
    study = get_object_or_404(Study, pk=study_id)  # rejection should also be handled in decorator
    survey = get_object_or_404(Survey, pk=survey_id, deleted=False)
    participant = get_object_or_404(Participant, patient_id=patient_id, study=study)
    fcm_token = participant.get_fcm_token()
    p_os = participant.os_type  # "participant os"
    now = timezone.now()
    
    # setup exit details
    error_message = f'Could not send notification to {participant.patient_id}'
    return_redirect = redirect(
        "participant_pages.participant_page", study_id=study_id, patient_id=participant.patient_id
    )
    
    # create an event for this attempt, update it on all exit scenarios
    unscheduled_event = ArchivedEvent(
        survey_archive=survey.archives.order_by("-archive_start").first(),  # the current survey archive
        participant=participant,
        schedule_type=f"manual - {request.session_researcher.username}"[:32],  # max length of field
        scheduled_time=now,
        response_time=None,
        status="resend clicked",
    )
    unscheduled_event.save()
    
    # failures
    if fcm_token is None:
        unscheduled_event.update(status="device has no registered token")
        messages.error(request, error_message)
        return return_redirect
    
    if not check_firebase_instance(require_android=p_os==ANDROID_API, require_ios=p_os==IOS_API):
        unscheduled_event.update(status="Push notifications not configured for participant device type")
        messages.error(request, error_message)
        return return_redirect
    
    message = messaging.Message(
        data={
            'type': 'survey',
            'survey_ids': json.dumps([survey.object_id]),
            'sent_time': now.strftime(API_TIME_FORMAT),
        },
        token=fcm_token.token,
    )
    
    # real error cases (raised directly when running locally, reported to sentry on a server)
    try:
        _response = messaging.send(message)
        unscheduled_event.update(status=ArchivedEvent.SUCCESS)
        messages.success(request, f'Successfully sent notification to {participant.patient_id}.')
    except FirebaseError as e:
        unscheduled_event.update(status=f"message send failed: {str(e)}")
        messages.error(request, error_message)
        with make_error_sentry(SentryTypes.elastic_beanstalk):
            raise
    except Exception:
        unscheduled_event.update(status="message send failed: unknown")  # presumably a bug
        messages.error(request, error_message)
        with make_error_sentry(SentryTypes.elastic_beanstalk):
            raise
    
    return return_redirect
