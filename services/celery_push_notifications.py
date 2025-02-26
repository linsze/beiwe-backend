import json
import random
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Tuple
from dateutil.tz import gettz
from django.utils import timezone
from firebase_admin.messaging import (AndroidConfig, Message, Notification, QuotaExceededError,
    send as send_notification, SenderIdMismatchError, ThirdPartyAuthError, UnregisteredError)

from config.settings import BLOCK_QUOTA_EXCEEDED_ERROR, PUSH_NOTIFICATION_ATTEMPT_COUNT
from constants.celery_constants import PUSH_NOTIFICATION_SEND_QUEUE
from constants.common_constants import API_TIME_FORMAT
from constants.message_strings import MESSAGE_SEND_SUCCESS
from constants.schedule_constants import ScheduleTypes
from constants.security_constants import OBJECT_ID_ALLOWED_CHARS
from constants.user_constants import ANDROID_API
from database.schedule_models import ScheduledEvent
from database.user_models_participant import (Participant, ParticipantFCMHistory,
    PushNotificationDisabledEvent)
from libs.celery_control import push_send_celery_app, safe_apply_async
from libs.firebase_config import check_firebase_instance
from libs.internal_types import DictOfStrStr, DictOfStrToListOfStr
from libs.schedules import set_next_weekly
from libs.sentry import make_error_sentry, SentryTypes

UTC = gettz("UTC")

PUSH_NOTIFICATION_LOGGING_ENABLED = False

def log(*args, **kwargs):
    if PUSH_NOTIFICATION_LOGGING_ENABLED:
        print(*args, **kwargs)

################################################################E###############
############################# PUSH NOTIFICATIONS ###############################
################################################################################

# TODO: make this a class
def get_surveys_and_schedules(now: datetime) -> Tuple[DictOfStrToListOfStr, DictOfStrToListOfStr, DictOfStrStr]:
    """ Mostly this function exists to reduce mess. returns:
    a mapping of fcm tokens to list of survey object ids
    a mapping of fcm tokens to list of schedule ids
    a mapping of fcm tokens to patient ids """
    log(f"\nchecking if any scheduled events are in the past (before {now})")
    
    # we need to find all possible events and convert them on a per-participant-timezone basis.
    # The largest timezone offset is +14?, but we will do one whole day and manually filter.
    tomorrow = now + timedelta(days=1)
    
    # get: schedule time is in the past for participants that have fcm tokens.
    # need to filter out unregistered fcms, database schema sucks for that, do it in python. its fine.
    query = ScheduledEvent.objects.filter(
        # core
        scheduled_time__lte=tomorrow,
        participant__fcm_tokens__isnull=False,
        # safety
        participant__deleted=False,
        survey__deleted=False,
        # Shouldn't be necessary, placeholder containing correct lte count.
        # participant__push_notification_unreachable_count__lte=PUSH_NOTIFICATION_ATTEMPT_COUNT
        # added august 2022, part of checkins
        deleted=False,
    ).values_list(
        "scheduled_time",
        "survey__object_id",
        "survey__study__timezone_name",
        "participant__fcm_tokens__token",
        "pk",
        "participant__patient_id",
        "participant__fcm_tokens__unregistered",
        "participant__timezone_name",
        "participant__unknown_timezone",
    )
    
    # we need a mapping of fcm tokens (a proxy for participants) to surveys and schedule ids (pks)
    surveys = defaultdict(list)
    schedules = defaultdict(list)
    patient_ids = {}
    
    # unregistered means that the FCM push notification token has been marked as unregistered, which
    # is fcm-speak for invalid push notification token. It's probably possible to update the query
    # to bad fcm tokens, but it becomes complex. The filtering is fast enough in Python.
    unregistered: bool
    fcm: str  # fcm token
    patient_id: str
    survey_obj_id: str
    scheduled_time: datetime  # in UTC
    schedule_id: int
    study_tz_name: str
    participant_tz_name: str
    participant_has_bad_tz: bool
    for scheduled_time, survey_obj_id, study_tz_name, fcm, schedule_id, patient_id, unregistered, participant_tz_name, participant_has_bad_tz in query:
        log("\nchecking scheduled event:")
        log("unregistered:", unregistered)
        log("fcm:", fcm)
        log("patient_id:", patient_id)
        log("survey_obj_id:", survey_obj_id)
        log("scheduled_time:", scheduled_time)
        log("schedule_id:", schedule_id)
        log("study_tz_name:", study_tz_name)
        log("participant_tz_name:", participant_tz_name)
        log("participant_has_bad_tz:", participant_has_bad_tz)
        
        # case: this instance has an outdated FCM credential, skip it.
        if unregistered:
            log("nope, unregistered fcm token")
            continue
        
        # The participant and study timezones REALLY SHOULD be valid timezone names. If they aren't
        # valid then gettz's behavior is to return None; if gettz receives None or the empty string
        # then it returns UTC. In order to at-least-be-consistent we will coerce no timezone to UTC.
        # (At least gettz caches, so performance should be fine without adding complexity.)
        participant_tz = gettz(study_tz_name) if participant_has_bad_tz else gettz(participant_tz_name)
        participant_tz = participant_tz or UTC
        study_tz = gettz(study_tz_name) or UTC
        
        # ScheduledEvents are created in the study's timezone, and in the database they are
        # normalized to UTC. Convert it to the study timezone time - we'll call that canonical time
        # - which will be the time of day assigned on the survey page. Then time-shift that into the
        # participant's timezone, and check if That value is in the past.
        canonical_time = scheduled_time.astimezone(study_tz)
        participant_time = canonical_time.replace(tzinfo=participant_tz)
        log("canonical_time:", canonical_time)
        log("participant_time:", participant_time)
        if participant_time > now:
            log("nope, participant time is considered in the future")
            log(f"{now} > {participant_time}")
            continue
        log("yup, participant time is considered in the past")
        log(f"{now} <= {participant_time}")
        surveys[fcm].append(survey_obj_id)
        schedules[fcm].append(schedule_id)
        patient_ids[fcm] = patient_id
    
    return dict(surveys), dict(schedules), patient_ids


def create_push_notification_tasks():
    # we reuse the high level strategy from data processing celery tasks, see that documentation.
    expiry = (datetime.utcnow() + timedelta(minutes=5)).replace(second=30, microsecond=0)
    now = timezone.now()
    surveys, schedules, patient_ids = get_surveys_and_schedules(now)
    print("Surveys:", surveys, sep="\n\t")
    print("Schedules:", schedules, sep="\n\t")
    print("Patient_ids:", patient_ids, sep="\n\t")
    
    with make_error_sentry(sentry_type=SentryTypes.data_processing):
        if not check_firebase_instance():
            print("Firebase is not configured, cannot queue notifications.")
            return
        
        # surveys and schedules are guaranteed to have the same keys, assembling the data structures
        # is a pain, so it is factored out. sorry, but not sorry. it was a mess.
        for fcm_token in surveys.keys():
            print(f"Queueing up push notification for user {patient_ids[fcm_token]} for {surveys[fcm_token]}")
            safe_apply_async(
                celery_send_push_notification,
                args=[fcm_token, surveys[fcm_token], schedules[fcm_token]],
                max_retries=0,
                expires=expiry,
                task_track_started=True,
                task_publish_retry=False,
                retry=False,
            )


@push_send_celery_app.task(queue=PUSH_NOTIFICATION_SEND_QUEUE)
def celery_send_push_notification(fcm_token: str, survey_obj_ids: List[str], schedule_pks: List[int]):
    ''' Celery task that sends push notifications. Note that this list of pks may contain duplicates.'''
    # Oh.  The reason we need the patient_id is so that we can debug anything ever. lol...
    patient_id = ParticipantFCMHistory.objects.filter(token=fcm_token) \
        .values_list("participant__patient_id", flat=True).get()
    
    with make_error_sentry(sentry_type=SentryTypes.data_processing):
        if not check_firebase_instance():
            print("Firebase credentials are not configured.")
            return
        
        # use the earliest timed schedule as our reference for the sent_time parameter.  (why?)
        participant = Participant.objects.get(patient_id=patient_id)
        schedules = ScheduledEvent.objects.filter(pk__in=schedule_pks)
        reference_schedule = schedules.order_by("scheduled_time").first()
        survey_obj_ids = list(set(survey_obj_ids))  # Dedupe-dedupe
        
        print(f"Sending push notification to {patient_id} for {survey_obj_ids}...")
        try:
            send_push_notification(participant, reference_schedule, survey_obj_ids, fcm_token)
        # error types are documented at firebase.google.com/docs/reference/fcm/rest/v1/ErrorCode
        except UnregisteredError:
            print("\nUnregisteredError\n")
            # Is an internal 404 http response, it means the token that was used has been disabled.
            # Mark the fcm history as out of date, return early.
            ParticipantFCMHistory.objects.filter(token=fcm_token).update(unregistered=timezone.now())
            return
        
        except QuotaExceededError as e:
            # Limits are very high, this should be impossible. Reraise because this requires
            # sysadmin attention and probably new development to allow multiple firebase
            # credentials. Read comments in settings.py if toggling.
            if BLOCK_QUOTA_EXCEEDED_ERROR:
                failed_send_handler(participant, fcm_token, str(e), schedules)
                return
            else:
                raise
        
        except ThirdPartyAuthError as e:
            print("\nThirdPartyAuthError\n")
            failed_send_handler(participant, fcm_token, str(e), schedules)
            # This means the credentials used were wrong for the target app instance.  This can occur
            # both with bad server credentials, and with bad device credentials.
            # We have only seen this error statement, error name is generic so there may be others.
            if str(e) != "Auth error from APNS or Web Push Service":
                raise
            return
        
        except SenderIdMismatchError as e:
            # In order to enhance this section we will need exact text of error messages to handle
            # similar error cases. (but behavior shouldn't be broken anymore, failed_send_handler
            # executes.)
            print("\nSenderIdMismatchError:\n")
            print(e)
            failed_send_handler(participant, fcm_token, str(e), schedules)
            return
        
        except ValueError as e:
            print("\nValueError\n")
            # This case occurs ever? is tested for in check_firebase_instance... weird race condition?
            # Error should be transient, and like all other cases we enqueue the next weekly surveys regardless.
            if "The default Firebase app does not exist" in str(e):
                enqueue_weekly_surveys(participant, schedules)
                return
            else:
                raise
        
        except Exception as e:
            failed_send_handler(participant, fcm_token, str(e), schedules)
            return
        
        success_send_handler(participant, fcm_token, schedules)


def send_push_notification(
        participant: Participant, reference_schedule: ScheduledEvent, survey_obj_ids: List[str],
        fcm_token: str
) -> str:
    """ Contains the body of the code to send a notification  """
    # we include a nonce in case of notification deduplication, and a schedule_uuid to for the
    #  checkin after the push notification is sent.
    data_kwargs = {
        'nonce': ''.join(random.choice(OBJECT_ID_ALLOWED_CHARS) for _ in range(32)),
        'sent_time': reference_schedule.scheduled_time.strftime(API_TIME_FORMAT),
        'type': 'survey',
        'survey_ids': json.dumps(survey_obj_ids),
        'schedule_uuid': reference_schedule.uuid or ""
    }
    
    if participant.os_type == ANDROID_API:
        message = Message(android=AndroidConfig(data=data_kwargs, priority='high'), token=fcm_token)
    else:
        display_message = \
            "You have a survey to take." if len(survey_obj_ids) == 1 else "You have surveys to take."
        message = Message(
            data=data_kwargs,
            token=fcm_token,
            notification=Notification(title="Beiwe", body=display_message),
        )
    send_notification(message)


def success_send_handler(participant: Participant, fcm_token: str, schedules: List[ScheduledEvent]):
    # If the query was successful archive the schedules.  Clear the fcm unregistered flag
    # if it was set (this shouldn't happen. ever. but in case we hook in a ui element we need it.)
    print(f"Push notification send succeeded for {participant.patient_id}.")
    
    # this condition shouldn't occur.  Leave in, this case would be super stupid to diagnose.
    fcm_hist: ParticipantFCMHistory = ParticipantFCMHistory.objects.get(token=fcm_token)
    if fcm_hist.unregistered is not None:
        fcm_hist.unregistered = None
        fcm_hist.save()
    
    participant.push_notification_unreachable_count = 0
    participant.save()
    
    create_archived_events(schedules, status=MESSAGE_SEND_SUCCESS)
    enqueue_weekly_surveys(participant, schedules)


def failed_send_handler(
        participant: Participant, fcm_token: str, error_message: str, schedules: List[ScheduledEvent]
):
    """ Contains body of code for unregistering a participants push notification behavior.
        Participants get reenabled when they next touch the app checkin endpoint. """
    
    if participant.push_notification_unreachable_count >= PUSH_NOTIFICATION_ATTEMPT_COUNT:
        now = timezone.now()
        fcm_hist: ParticipantFCMHistory = ParticipantFCMHistory.objects.get(token=fcm_token)
        fcm_hist.unregistered = now
        fcm_hist.save()
        
        PushNotificationDisabledEvent(
            participant=participant, timestamp=now,
            count=participant.push_notification_unreachable_count
        ).save()
        
        # disable the credential
        participant.push_notification_unreachable_count = 0
        participant.save()
        
        print(f"Participant {participant.patient_id} has had push notifications "
              f"disabled after {PUSH_NOTIFICATION_ATTEMPT_COUNT} failed attempts to send.")
    
    else:
        now = None
        participant.push_notification_unreachable_count += 1
        participant.save()
        print(f"Participant {participant.patient_id} has had push notifications failures "
              f"incremented to {participant.push_notification_unreachable_count}.")
    
    create_archived_events(schedules, status=error_message, created_on=now)
    enqueue_weekly_surveys(participant, schedules)


def create_archived_events(schedules: List[ScheduledEvent], status: str, created_on: datetime = None):
    # """ Populates event history, does not mark ScheduledEvents as deleted. """
    
    # TODO: We are currently blindly deleting after sending, this will be changed after the app is
    #  updated to provide uuid checkins on the download surveys endpoint.
    mark_as_deleted = status == MESSAGE_SEND_SUCCESS
    for scheduled_event in schedules:
        scheduled_event.archive(self_delete=mark_as_deleted, status=status, created_on=created_on)


def enqueue_weekly_surveys(participant: Participant, schedules: List[ScheduledEvent]):
    # set_next_weekly is idempotent until the next weekly event passes.
    # its perfectly safe (commit time) to have many of the same weekly survey be scheduled at once.
    for schedule in schedules:
        if schedule.get_schedule_type() == ScheduleTypes.weekly:
            set_next_weekly(participant, schedule.survey)


celery_send_push_notification.max_retries = 0  # requires the celerytask function object.
