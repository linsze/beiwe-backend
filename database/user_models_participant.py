from __future__ import annotations

import json
from datetime import datetime, timedelta, tzinfo
from pprint import pprint
from typing import Dict, Tuple, Union

from Cryptodome.PublicKey import RSA
from dateutil.tz import gettz
from django.core.validators import MinLengthValidator
from django.db import models
from django.db.models import Manager
from django.utils import timezone

from config.settings import DOMAIN_NAME
from constants.data_stream_constants import IDENTIFIERS
from constants.user_constants import ANDROID_API, IOS_API, OS_TYPE_CHOICES
from database.common_models import UtilityModel
from database.models import TimestampedModel
from database.study_models import Study
from database.user_models_common import AbstractPasswordUser
from database.validators import ID_VALIDATOR
from libs.firebase_config import check_firebase_instance
from libs.security import (compare_password, device_hash, django_password_components,
    generate_easy_alphanumeric_string)


# This is an import hack to improve IDE assistance.  Most of these imports are cyclical and fail at
# runtime, but the exception is caught.  The IDE's parser doesn't know it would fail and just uses
# the information correctly, allowing us to use them in type annotations.  There are no weird
# runtime errors because type annotations are Completely Elided before runtime.  Then, with these
# annotations, your IDE is able to provide type inferencing assistance throughout the codebase.
#
# By attaching some extra type declarations to model classes for django's dynamically generated
# properties (example: "scheduled_events" on the Participant class below) we magically get that type
# information almost everywhere.  (These can be generated for you automatically by running `python
# run_script.py generate_relation_hax` and pasting as required.)
#
# If you must to use an unimportable class (like ArchivedEvent in the notification_events()
# convenience method on Participants below) you will need to add a local import.
try:
    from database.models import (ArchivedEvent, ChunkRegistry, EncryptionErrorMetadata,
        FileToProcess, ForestTask, InterventionDate, IOSDecryptionKey, LineEncryptionError,
        ScheduledEvent, StudyField, SummaryStatisticDaily, UploadTracking)
except ImportError:
    pass


class Participant(AbstractPasswordUser):
    """ The Participant database object contains the password hashes and unique usernames of any
    participants in the study, as well as information about the device the participant is using.
    A Participant uses mobile, so their passwords are hashed accordingly. """
    DESIRED_ALGORITHM = "sha1"   # Yes, Bad, but this password doesn't actually protect access to data.
    DESIRED_ITERATIONS = 1000  # We will be completely reworking participant authentication soon anyway.
    
    patient_id = models.CharField(
        max_length=8, unique=True, validators=[ID_VALIDATOR],
        help_text='Eight-character unique ID with characters chosen from 1-9 and a-z'
    )
    device_id = models.CharField(
        max_length=256, blank=True,
        help_text='The ID of the device that the participant is using for the study, if any.'
    )
    os_type = models.CharField(
        max_length=16, choices=OS_TYPE_CHOICES, blank=True,
        help_text='The type of device the participant is using, if any.'
    )
    study: Study = models.ForeignKey(
        Study, on_delete=models.PROTECT, related_name='participants', null=False
    )
    # see timezone property
    timezone_name = models.CharField(  # Warning: this is not used yet.
        max_length=256, default="America/New_York", null=False, blank=False
    )
    unknown_timezone = models.BooleanField(default=True)  # flag for using participant's timezone.
    
    push_notification_unreachable_count = models.SmallIntegerField(default=0, null=False, blank=False)
    
    # TODO: clean out or maybe rename these fields to distinguish from last_updated? also wehave two survey checkin timestamps
    # new checkin logic
    first_push_notification_checkin = models.DateTimeField(null=True, blank=True)
    last_push_notification_checkin = models.DateTimeField(null=True, blank=True)
    last_survey_checkin = models.DateTimeField(null=True, blank=True)
    
    # pure tracking
    last_get_latest_surveys = models.DateTimeField(null=True, blank=True)
    last_upload = models.DateTimeField(null=True, blank=True)
    last_register_user = models.DateTimeField(null=True, blank=True)
    last_set_password = models.DateTimeField(null=True, blank=True)
    last_set_fcm_token = models.DateTimeField(null=True, blank=True)
    last_get_latest_device_settings = models.DateTimeField(null=True, blank=True)
    
    # participant device tracking
    last_version_code = models.CharField(max_length=32, blank=True, null=True)
    last_version_name = models.CharField(max_length=32, blank=True, null=True)
    last_os_version = models.CharField(max_length=32, blank=True, null=True)
    device_status_report = models.TextField(default=None, null=True, blank=True)
    
    deleted = models.BooleanField(default=False)
    
    # "Unregistered" means the participant is blocked from uploading further data; retired.
    unregistered = models.BooleanField(default=False)
    easy_enrollment = models.BooleanField(default=False)
    
    # related field typings (IDE halp)
    archived_events: Manager[ArchivedEvent]
    chunk_registries: Manager[ChunkRegistry]
    deletion_event: Manager[ParticipantDeletionEvent]
    fcm_tokens: Manager[ParticipantFCMHistory]
    field_values: Manager[ParticipantFieldValue]
    files_to_process: Manager[FileToProcess]
    intervention_dates: Manager[InterventionDate]
    scheduled_events: Manager[ScheduledEvent]
    upload_trackers: Manager[UploadTracking]
    # undeclared:
    encryptionerrormetadata_set: Manager[EncryptionErrorMetadata]  # TODO: remove when ios stops erroring
    foresttask_set: Manager[ForestTask]
    iosdecryptionkey_set: Manager[IOSDecryptionKey]  # TODO: remove when ios stops erroring
    lineencryptionerror_set: Manager[LineEncryptionError]  # TODO: remove when ios stops erroring?
    pushnotificationdisabledevent_set: Manager[PushNotificationDisabledEvent]
    summarystatisticdaily_set: Manager[SummaryStatisticDaily]
    
    @property
    def _recents(self) -> Dict[str, Union[str, datetime]]:
        self.refresh_from_db()
        now = timezone.now()
        return {
            "last_version_code": self.last_version_code,
            "last_version_name": self.last_version_name,
            "last_os_version": self.last_os_version,
            "last_get_latest_surveys": f"{(now - self.last_get_latest_surveys).total_seconds() // 60} minutes ago" if self.last_get_latest_surveys else None,
            "last_push_notification_checkin": f"{(now - self.last_push_notification_checkin).total_seconds() // 60} minutes ago" if self.last_push_notification_checkin else None,
            "last_register_user": f"{(now - self.last_register_user).total_seconds() // 60} minutes ago" if self.last_register_user else None,
            "last_set_fcm_token": f"{(now - self.last_set_fcm_token).total_seconds() // 60} minutes ago" if self.last_set_fcm_token else None,
            "last_set_password": f"{(now - self.last_set_password).total_seconds() // 60} minutes ago" if self.last_set_password else None,
            "last_survey_checkin": f"{(now - self.last_survey_checkin).total_seconds() // 60} minutes ago" if self.last_survey_checkin else None,
            "last_upload": f"{(now - self.last_upload).total_seconds() // 60} minutes ago" if self.last_upload else None,
            "last_get_latest_device_settings": f"{(now - self.last_get_latest_device_settings).total_seconds() // 60} minutes ago" if self.last_get_latest_device_settings else None,
        }
    
    @property
    def timezone(self) -> tzinfo:
        """ So pytz.timezone("America/New_York") provides a tzinfo-like object that is wrong by 4
        minutes.  That's insane.  The dateutil gettz function doesn't have that fun insanity. """
        return gettz(self.timezone_name)
    
    def try_set_timezone(self, new_timezone_name: str):
        """ Use dateutil to test whether the timezone is valid, only set timezone_name field if it
        is. Set unknown_timezone to True if the timezone is invalid, false if it is valid. """
        if new_timezone_name is None or new_timezone_name == "":
            raise TypeError("None and the empty string actually coerce to the UTC timezone, which is weird and undesireable.")
        
        new_tz = gettz(new_timezone_name)
        if new_tz is None:
            # if study timezone is null or empty, use the default timezone.
            study_timezone_name = self.study.timezone_name
            if study_timezone_name is None or study_timezone_name == "":
                study_timezone_name = Participant._meta.get_field("timezone_name").default
            self.update_only(unknown_timezone=True, timezone_name=study_timezone_name)
        else:
            # force setting unknown_timezone false if the value is valid
            self.update_only(unknown_timezone=False, timezone_name=new_timezone_name)
    
    @classmethod
    def create_with_password(cls, **kwargs) -> Tuple[str, str]:
        """ Creates a new participant with randomly generated patient_id and password. """
        # Ensure that a unique patient_id is generated. If it is not after
        # twenty tries, raise an error.
        patient_id = generate_easy_alphanumeric_string()
        for _ in range(20):
            if not cls.objects.filter(patient_id=patient_id).exists():
                # If patient_id does not exist in the database already
                break
            patient_id = generate_easy_alphanumeric_string()
        else:
            raise RuntimeError('Could not generate unique Patient ID for new Participant.')
        
        # Create a Participant, and generate for them a password
        participant = cls(patient_id=patient_id, **kwargs)
        password = participant.reset_password()  # this saves participant
        return patient_id, password
    
    def generate_hash_and_salt(self, password: bytes) -> Tuple[bytes, bytes]:
        """ The Participant's device runs sha256 on the input password before sending it. """
        return super().generate_hash_and_salt(device_hash(password))
    
    def debug_validate_password(self, compare_me: str) -> bool:
        """ Hardcoded values for a test, this is for a test. """
        _algorithm, _iterations, password, salt = django_password_components(self.password)
        return compare_password('sha1', 1000, device_hash(compare_me.encode()), password, salt)
    
    def assign_fcm_token(self, fcm_instance_id: str):
        ParticipantFCMHistory.objects.create(participant=self, token=fcm_instance_id)
    
    def get_valid_fcm_token(self) -> ParticipantFCMHistory:
        try:
            return self.fcm_tokens.get(unregistered__isnull=True)
        except ParticipantFCMHistory.DoesNotExist:
            return None
    
    def notification_events(self, **archived_event_filter_kwargs) -> Manager[ArchivedEvent]:
        """ convenience methodd for use debugging in the terminal mostly. """
        from database.schedule_models import ArchivedEvent
        return ArchivedEvent.objects.filter(participant=self) \
            .filter(**archived_event_filter_kwargs).order_by("-scheduled_time")
    
    def get_private_key(self) -> RSA.RsaKey:
        from libs.s3 import get_client_private_key  # weird import triangle
        return get_client_private_key(self.patient_id, self.study.object_id)
    
    def s3_retrieve(self, s3_path: str) -> bytes:
        from libs.s3 import s3_retrieve
        raw_path = s3_path.startswith(self.study.object_id)
        return s3_retrieve(s3_path, self, raw_path=raw_path)
    
    @property
    def is_dead(self) -> bool:
        return self.deleted or self.has_deletion_event
    
    @property
    def has_deletion_event(self) -> bool:
        try:
            self.deletion_event
            return True
        except ParticipantDeletionEvent.DoesNotExist:
            return False
    
    @property
    def participant_push_enabled(self) -> bool:
        return (
            self.os_type == ANDROID_API and check_firebase_instance(require_android=True) or
            self.os_type == IOS_API and check_firebase_instance(require_ios=True)
        )
    
    @property
    def participant_page(self):
        """ returns a url for the participant page for this user (debugging function) """
        from libs.http_utils import easy_url  # import triangle
        return f"https://{DOMAIN_NAME}" + easy_url(
            "participant_pages.participant_page", self.study.id, self.patient_id
        )
    
    @property
    def pprint(self):
        d = self._pprint()
        dsr = d.pop("device_status_report")
        pprint(d)
        # it can be None, and empty string
        if dsr:
            print("\nDevice Status Report:")
            pprint(json.loads(dsr))
        else:
            print("\n(No device status report.)")
    
    @property
    def get_identifiers(self):
        for identifier in self.chunk_registries.filter(data_type=IDENTIFIERS).order_by("created_on"):
            print(identifier.s3_retrieve().decode())
    
    def __str__(self) -> str:
        return f'{self.patient_id} of Study "{self.study.name}"'


class PushNotificationDisabledEvent(UtilityModel):
    # There may be many events
    # this is (currently) purely for record keeping.
    participant: Participant = models.ForeignKey(Participant, null=False, on_delete=models.PROTECT)
    count = models.IntegerField(null=False)
    timestamp = models.DateTimeField(null=False, blank=False, auto_now_add=True, db_index=True)


class ParticipantFCMHistory(TimestampedModel):
    # by making the token unique the solution to problems becomes "reinstall the app"
    participant: Participant = models.ForeignKey("Participant", null=False, on_delete=models.PROTECT, related_name="fcm_tokens")
    token = models.CharField(max_length=256, blank=False, null=False, db_index=True, unique=True,
                             validators=[MinLengthValidator(1)])
    unregistered = models.DateTimeField(null=True, blank=True)


class ParticipantFieldValue(UtilityModel):
    """ These objects can be deleted.  These are values for per-study custom fields for users """
    participant: Participant = models.ForeignKey(Participant, on_delete=models.PROTECT, related_name='field_values')
    field: StudyField = models.ForeignKey('StudyField', on_delete=models.CASCADE, related_name='field_values')
    value = models.TextField(null=False, blank=True, default="")
    
    class Meta:
        unique_together = (("participant", "field"),)


class ParticipantDeletionEvent(TimestampedModel):
    """ This is a list of participants that have been deleted, but we are keeping around for a while
    in case we need to restore them. """
    participant: Participant = models.OneToOneField(Participant, on_delete=models.PROTECT, related_name="deletion_event")
    files_deleted_count = models.BigIntegerField(null=False, blank=False, default=0)
    purge_confirmed_time = models.DateTimeField(null=True, blank=True, db_index=True)
    
    @classmethod
    def summary(cls):
        """ Provides a simple overview of the current state of the deletion queue. """
        now = timezone.now()
        now_minus_30 = now - timedelta(minutes=30)
        now_minus_6 = now - timedelta(minutes=6)
        past_24_hours = now - timedelta(hours=24)
        base = cls.objects.order_by("participant__patient_id")
        base_unfinished = base.filter(purge_confirmed_time__isnull=True).exclude(created_on__gt=now_minus_30)
        
        # deletion events with a created_on timestamp less than 30 minutes ago will have
        # last_updated of almost same age, and will not run.
        held_events = base.filter(created_on__gt=now_minus_30)
        print(
            f"There are {held_events.count()} participants with held deletion events:\n"
            f"{', '.join(p for p in held_events.values_list('participant__patient_id', flat=True))}"
            "\n"
        )
        
        # deletion events with a last updated time older than 30 minutes are eligible for deletion.
        # (excludes held events)
        eligible_events = base_unfinished.filter(last_updated__lt=now_minus_30)
        print(
            f"There are {eligible_events.count()} participants eligible for deletion:\n"
            f"{', '.join(p for p in eligible_events.values_list('participant__patient_id', flat=True))}"
            "\n"
        )
        
        # active deletion events are those with a last updated timestamp more recent than 6 minutes
        # ago (excludes held events).
        active_events = base_unfinished.filter(last_updated__gt=now_minus_6)
        print(
            f"There are {active_events.count()} potentially active deletion events:\n"
            f"{', '.join(p for p in active_events.values_list('participant__patient_id', flat=True))}"
            "\n"
        )
        
        # finished events are any with a purge_confirmed_time.
        finished_events = base.filter(purge_confirmed_time__isnull=False)
        finished_24 = finished_events.filter(purge_confirmed_time__gt=past_24_hours)
        print(
            f"There are {finished_events.count()} finished deletion events, with "
            f"{finished_24.count()} in the past 24 hours:\n"
            f"{', '.join(p for p in finished_24.values_list('participant__patient_id', flat=True))}"
        )
