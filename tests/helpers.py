import subprocess
import uuid
from datetime import date, datetime, timedelta
from typing import List, Tuple

from django.db.models import (AutoField, CharField, DateField, FloatField, ForeignKey, IntegerField,
    TextField)
from django.http.response import HttpResponse
from django.utils import timezone

from config.django_settings import STATIC_ROOT
from constants.common_constants import BEIWE_PROJECT_ROOT
from constants.data_stream_constants import IDENTIFIERS
from constants.forest_constants import DefaultForestParameters, ForestTaskStatus, ForestTree
from constants.message_strings import MESSAGE_SEND_SUCCESS
from constants.schedule_constants import ScheduleTypes
from constants.testing_constants import REAL_ROLES
from constants.user_constants import ANDROID_API, IOS_API, NULL_OS, ResearcherRole
from database.common_models import generate_objectid_string
from database.data_access_models import ChunkRegistry, FileToProcess
from database.schedule_models import (AbsoluteSchedule, ArchivedEvent, Intervention,
    InterventionDate, RelativeSchedule, ScheduledEvent, WeeklySchedule)
from database.study_models import DeviceSettings, Study, StudyField
from database.survey_models import Survey
from database.tableau_api_models import ForestParameters, ForestTask, SummaryStatisticDaily
from database.user_models_participant import (Participant, ParticipantDeletionEvent,
    ParticipantFCMHistory, ParticipantFieldValue)
from database.user_models_researcher import Researcher, StudyRelation
from libs.internal_types import Schedule
from libs.schedules import set_next_weekly
from libs.security import device_hash, generate_easy_alphanumeric_string


CURRENT_TEST_HTML_FILEPATH = BEIWE_PROJECT_ROOT + "private/current_test_page.html"
ABS_STATIC_ROOT = (BEIWE_PROJECT_ROOT + STATIC_ROOT).encode()


class ReferenceObjectMixin:
    """ This class implements DB object creation.  Some objects have convenience property wrappers
    because they are so common. """
    
    DEFAULT_RESEARCHER_NAME = "session_researcher"
    DEFAULT_RESEARCHER_PASSWORD = "abcABC123!@#" * 2  # we want a very long password for testing
    DEFAULT_STUDY_NAME = "session_study"
    DEFAULT_SURVEY_OBJECT_ID = 'u1Z3SH7l2xNsw72hN3LnYi96'
    DEFAULT_PARTICIPANT_NAME = "patient1"  # has to be 8 characters
    DEFAULT_PARTICIPANT_PASSWORD = "abcABC123"
    DEFAULT_PARTICIPANT_PASSWORD_HASHED = device_hash(DEFAULT_PARTICIPANT_PASSWORD.encode()).decode()
    DEFAULT_PARTICIPANT_DEVICE_ID = "default_device_id"
    DEFAULT_INTERVENTION_NAME = "default_intervention_name"
    DEFAULT_FCM_TOKEN = "abc123"
    SOME_SHA1_PASSWORD_COMPONENTS = 'sha1$1000$zsk387ts02hDMRAALwL2SL3nVHFgMs84UcZRYIQWYNQ=$hllJauvRYDJMQpXQKzTdwQ=='
    DEFAULT_STUDY_FIELD_NAME = "default_study_field_name"
    DEFAULT_PARTICIPANT_FIELD_VALUE = "default_study_field_value"
    # this needs to be a dynamic property in order for the time_machine library to work
    @property
    def CURRENT_DATE(self) -> datetime:
        return timezone.now().today().date()
    
    # For all defaults make sure to maintain the pattern that includes the use of the save function,
    # this codebase implements a special save function that validates before passing through.
    
    #
    ## Study objects
    #
    @property
    def session_study(self) -> Study:
        """ Gets or creates a default study object.  Note that this has the side effect of creating
        a study settings db object as well.  This is a default object, and will be auto-populated
        in scenarios where such an object is required but not provided. """
        try:
            return self._default_study
        except AttributeError:
            pass
        self._default_study = self.generate_study(self.DEFAULT_STUDY_NAME)
        return self._default_study
    
    @property
    def default_study(self):
        """ alias for session_study """
        return self.session_study
    
    def generate_study(
        self, name: str, encryption_key: str = None, object_id: str = None, is_test: bool = None,
        forest_enabled: bool = None
    ):
        study = Study(
            name=name,
            encryption_key=encryption_key or "thequickbrownfoxjumpsoverthelazy",
            object_id=object_id or generate_objectid_string(),
            is_test=is_test or True,
            forest_enabled=forest_enabled or True,
            timezone_name="UTC",
            deleted=False,
        )
        study.save()
        return study
    
    def set_session_study_relation(
        self, relation: ResearcherRole = ResearcherRole.researcher
    ) -> StudyRelation:
        """ Applies the study relation to the session researcher to the session study. """
        if hasattr(self, "_default_study_relation"):
            raise Exception("can only be called once per test (currently?)")
        
        self._default_study_relation = self.generate_study_relation(
            self.session_researcher, self.session_study, relation
        )
        return self._default_study_relation
    
    def generate_study_relation(self, researcher: Researcher, study: Study, relation: str) -> StudyRelation:
        """ Creates a study relation based on the input values, returns it. """
        if relation is None:
            researcher.study_relations.filter(study=self.session_study).delete()
            return relation
        
        if relation == ResearcherRole.site_admin:
            researcher.update(site_admin=True)
            return relation
        relation: StudyRelation = StudyRelation(researcher=researcher, study=study, relationship=relation)
        relation.save()
        return relation
    
    # I seem to have built this and then forgotten about it because I stuck in somewhere weird.
    def assign_role(self, researcher: Researcher, role: ResearcherRole):
        """ Helper function to assign a user role to a Researcher.  Clears all existing roles on
        that user. """
        if role in REAL_ROLES:
            researcher.study_relations.all().delete()
            self.generate_study_relation(researcher, self.session_study, role)
            researcher.update(site_admin=False)
        elif role is None:
            researcher.study_relations.all().delete()
            researcher.update(site_admin=False)
        elif role == ResearcherRole.site_admin:
            researcher.study_relations.all().delete()
            researcher.update(site_admin=True)
    
    #
    ## Researcher objects
    #
    @property
    def session_researcher(self) -> Researcher:
        """ Gets or creates the session researcher object.  This is a default object, and will be
        auto-populated in scenarios where such an object is required but not provided.  """
        try:
            return self._default_researcher
        except AttributeError:
            pass
        self._default_researcher = self.generate_researcher(self.DEFAULT_RESEARCHER_NAME)
        return self._default_researcher
    
    def generate_researcher(
        self, name: str = None, relation_to_session_study: str = None
    ) -> Researcher:
        """ Generate a researcher based on the parameters provided, relation_to_session_study is
        optional. """
        researcher = Researcher(
            username=name or generate_easy_alphanumeric_string(),
            password=self.SOME_SHA1_PASSWORD_COMPONENTS,
            access_key_secret=self.SOME_SHA1_PASSWORD_COMPONENTS,
            site_admin=relation_to_session_study == ResearcherRole.site_admin,
            password_force_reset=False,  # is True by default, makes no sense in a test context
        )
        # set password saves...
        researcher.set_password(self.DEFAULT_RESEARCHER_PASSWORD)
        if relation_to_session_study not in (None, ResearcherRole.site_admin):
            self.generate_study_relation(researcher, self.session_study, relation_to_session_study)
        
        return researcher
    
    #
    ## Objects for Studies
    #
    
    @property
    def default_survey(self) -> Survey:
        """ Creates a survey with no content attached to the session study. """
        try:
            return self._default_survey
        except AttributeError:
            pass
        self._default_survey = self.generate_survey(
            self.session_study, Survey.TRACKING_SURVEY, self.DEFAULT_SURVEY_OBJECT_ID,
        )
        return self._default_survey
    
    def generate_survey(self, study: Study, survey_type: str, object_id: str = None, **kwargs) -> Survey:
        survey = Survey(
            study=study,
            survey_type=survey_type,
            object_id=object_id or generate_objectid_string(),
            **kwargs
        )
        survey.save()
        return survey
    
    @property
    def session_device_settings(self) -> DeviceSettings:
        """ Providing the comment about using the save() pattern is observed, this cannot fail. """
        return self.session_study.device_settings
    
    @property
    def default_intervention(self) -> Intervention:
        try:
            return self._default_intervention
        except AttributeError:
            pass
        self._default_intervention = self.generate_intervention(
            self.session_study, self.DEFAULT_INTERVENTION_NAME
        )
        return self._default_intervention
    
    def generate_intervention(self, study: Study, name: str) -> Intervention:
        intervention = Intervention(study=study, name=name)
        intervention.save()
        return intervention
    
    @property
    def default_study_field(self) -> StudyField:
        try:
            return self._default_study_field
        except AttributeError:
            pass
        self._default_study_field = self.generate_study_field(
            self.default_study, self.DEFAULT_STUDY_FIELD_NAME
        )
        return self._default_study_field
    
    def generate_study_field(self, study: Study, name: str) -> StudyField:
        study_field = StudyField(study=study, field_name=name)
        study_field.save()
        return study_field
    
    #
    ## Participant objects
    #
    
    @property
    def default_participant(self) -> Participant:
        """ Creates a participant object on the session study.  This is a default object, and will
        be auto-populated in scenarios where such an object is required but not provided. """
        try:
            return self._default_participant
        except AttributeError:
            pass
        self._default_participant = self.generate_participant(
            self.session_study, self.DEFAULT_PARTICIPANT_NAME
        )
        return self._default_participant
    
    @property
    def populate_default_fcm_token(self) -> ParticipantFCMHistory:
        token = ParticipantFCMHistory(
            token=self.DEFAULT_FCM_TOKEN, participant=self.default_participant
        )
        token.save()
        return token
    
    @property
    def default_participant_field_value(self) -> StudyField:
        try:
            return self._default_participant_field_value
        except AttributeError:
            pass
        self._default_participant_field_value = self.generate_participant_field_value(
            self.default_study_field, self.default_participant, self.DEFAULT_PARTICIPANT_FIELD_VALUE
        )
        return self._default_participant_field_value
    
    def generate_participant_field_value(
        self, study_field: StudyField, participant: Participant, value: str
    ) -> ParticipantFieldValue:
        pfv = ParticipantFieldValue(participant=participant, field=study_field, value=value)
        pfv.save()
        return pfv
    
    @property
    def generate_10_default_participants(self) -> List[Participant]:
        return [self.generate_participant(self.session_study) for _ in range(10)]
    
    def generate_participant(self, study: Study, patient_id: str = None, ios=False, device_id=None):
        participant = Participant(
            patient_id=patient_id or generate_easy_alphanumeric_string(),
            os_type=IOS_API if ios else ANDROID_API,
            study=study,
            device_id=device_id or self.DEFAULT_PARTICIPANT_DEVICE_ID,
            password=self.SOME_SHA1_PASSWORD_COMPONENTS,
        )
        participant.set_password(self.DEFAULT_PARTICIPANT_PASSWORD)  # saves
        return participant
    
    def generate_fcm_token(self, participant: Participant, unregistered_datetime: datetime = None):
        token = ParticipantFCMHistory(
            participant=participant,
            token="token-" + generate_easy_alphanumeric_string(),
            unregistered=unregistered_datetime,
        )
        token.save()
        return token
    
    @property
    def default_populated_intervention_date(self) -> InterventionDate:
        try:
            return self._default_populated_intervention_date
        except AttributeError:
            pass
        self._default_populated_intervention_date = \
            self.generate_intervention_date(
                self.default_participant, self.default_intervention, self.CURRENT_DATE
            )
        return self._default_populated_intervention_date
    
    @property
    def default_unpopulated_intervention_date(self) -> InterventionDate:
        try:
            return self._default_unpopulated_intervention_date
        except AttributeError:
            pass
        self._default_unpopulated_intervention_date = \
            self.generate_intervention_date(self.default_participant, self.default_intervention)
        return self._default_unpopulated_intervention_date
    
    def generate_intervention_date(
        self, participant: Participant, intervention: Intervention, date: date = None
    ) -> InterventionDate:
        intervention_date = InterventionDate(
            participant=participant, intervention=intervention, date=date
        )
        intervention_date.save()
        return intervention_date
    
    def generate_file_to_process(
        self, path: str, study: Study = None, participant: Participant = None,
        deleted: bool = False, os_type: str = NULL_OS,
    ):
        ftp = FileToProcess(
            s3_file_path=path,
            study=study or self._default_study,
            participant=participant or self.default_participant,
            deleted=deleted,
            os_type=os_type,
        )
        ftp.save()
        return ftp
    
    @property
    def default_participant_deletion_event(self):
        # note that the DEFAULT participant deletion object has its last_updated time backdated by
        # 42 minutes.  This is to make it easier to test with as the participant data deletion won't
        # start/restart until the last_updated time is at least 30 minutes ago.
        try:
            return self._default_participant_deletion_event
        except AttributeError:
            pass
        self._default_participant_deletion_event = self.generate_participant_deletion_event(
            self.default_participant, last_updated=timezone.now() - timedelta(minutes=42)
        )
        return self._default_participant_deletion_event
    
    def generate_participant_deletion_event(
        self, participant: Participant, deleted_count: int = 0, confirmed: datetime = None, last_updated: datetime = None
    ) -> ParticipantDeletionEvent:
        
        deletion_event = ParticipantDeletionEvent(
            participant=participant, files_deleted_count=deleted_count, purge_confirmed_time=confirmed
        )
        deletion_event.save()
        # logic to update the last_updated time is here because its an auto_now field
        if last_updated:
            ParticipantDeletionEvent.objects.filter(pk=deletion_event.pk).update(last_updated=last_updated)
        deletion_event.refresh_from_db()
        
        return deletion_event
    
    #
    # schedule and schedule-adjacent objects
    #
    def generate_archived_event(
        self, survey: Survey, participant: Participant, schedule_type: str = None,
        scheduled_time: datetime = None, status: str = None
    ):
        archived_event = ArchivedEvent(
            survey_archive=survey.archives.first(),
            participant=participant,
            schedule_type=schedule_type or ScheduleTypes.weekly,
            scheduled_time=scheduled_time or timezone.now(),
            status=status or MESSAGE_SEND_SUCCESS,
        )
        archived_event.save()
        return archived_event
    
    def generate_weekly_schedule(
        self, survey: Survey = None, day_of_week: int = 0, hour: int = 0, minute: int = 0
    ) -> WeeklySchedule:
        weekly = WeeklySchedule(
            survey=survey or self.default_survey,
            day_of_week=day_of_week,
            hour=hour,
            minute=minute,
        )
        weekly.save()
        return weekly
    
    @property
    def default_relative_schedule(self) -> RelativeSchedule:
        try:
            return self._default_relative_schedule
        except AttributeError:
            pass
        self._default_relative_schedule = \
            self.generate_relative_schedule(self.default_survey)
        return self._default_relative_schedule
    
    def generate_relative_schedule(
        self, survey: Survey, intervention: Intervention = None, days_after: int = 0,
        hour: int = 0, minute: int = 0,
    ) -> RelativeSchedule:
        relative = RelativeSchedule(
            survey=survey or self.default_survey,
            intervention=intervention or self.default_intervention,
            days_after=days_after,
            hour=hour,
            minute=minute,
        )
        relative.save()
        return relative
    
    def generate_absolute_schedule(
        self, a_date: date, survey: Survey = None, hour: int = 0, minute: int = 0,
    ) -> RelativeSchedule:
        absolute = AbsoluteSchedule(
            survey=survey or self.default_survey,
            date=a_date,
            hour=hour,
            minute=minute,
        )
        absolute.save()
        return absolute
    
    def generate_absolute_schedule_from_datetime(self, survey: Survey, a_dt: datetime):
        absolute = AbsoluteSchedule(
            survey=survey or self.default_survey,
            date=a_dt.date(),
            hour=a_dt.hour,
            minute=a_dt.minute,
        )
        absolute.save()
        return absolute
    
    def generate_easy_absolute_schedule_event_with_schedule(self, time: timedelta):
        """ Note that no intervention is marked, this just creates the schedule basics """
        schedule = self.generate_absolute_schedule_from_datetime(self.default_survey, time)
        return self.generate_scheduled_event(
            self.default_survey, self.default_participant, schedule, time
        )
    
    def generate_easy_relative_schedule_event_with_schedule(self, event_time_offset_now: timedelta):
        """ Note that no intervention is marked, this just creates the schedule basics """
        now = timezone.now() + event_time_offset_now
        schedule = self.generate_relative_schedule(
            self.default_survey,
            self.default_intervention,
            days_after=event_time_offset_now.days,
            hour=event_time_offset_now.seconds // 60 // 60,  # the offset isn't perfect but 
            minute=event_time_offset_now.seconds // 60 % 60,  # this is fine for tests...
        )
        return self.generate_scheduled_event(
            self.default_survey, self.default_participant, schedule, now
        )
    
    def generate_a_real_weekly_schedule_event_with_schedule(
        self, day_of_week: int = 0, hour: int = 0, minute: int = 0
    ) -> Tuple[ScheduledEvent, int]:
        """ The creation of weekly events is weird, it best to use the real machinery and build
        some unit tests for it. At time of documenting none exist, but there are some integration
        tests. """
        # 0 indexes to sunday, 6 indexes to saturday.
        self.generate_weekly_schedule(self.default_survey, day_of_week, hour, minute)
        return set_next_weekly(self.default_participant, self.default_survey)
    
    def generate_scheduled_event(
        self, survey: Survey, participant: Participant, schedule: Schedule, time: datetime,
        a_uuid: uuid.UUID = None
    ) -> ScheduledEvent:
        scheduled_event = ScheduledEvent(
            survey=survey,
            participant=participant,
            weekly_schedule=schedule if isinstance(schedule, WeeklySchedule) else None,
            relative_schedule=schedule if isinstance(schedule, RelativeSchedule) else None,
            absolute_schedule=schedule if isinstance(schedule, AbsoluteSchedule) else None,
            scheduled_time=time,
            deleted=False,
            uuid=a_uuid or uuid.uuid4(),
            checkin_time=None,
            most_recent_event=None,
        )
        scheduled_event.save()
        return scheduled_event
    
    #
    ## Forest objects
    #
    
    @property
    def default_forest_params(self) -> ForestParameters:
        """ Creates a default forest params object.  This is a default object, and will be
        auto-populated in scenarios where such an object is required but not provided. """
        try:
            return self._default_forest_params
        except AttributeError:
            pass
        self._default_forest_params = ForestParameters(
            name="default forest param",
            notes="this is junk",
            tree_name="jasmine",
            json_parameters=DefaultForestParameters.jasmine_defaults,
        )
        self._default_forest_params.save()
        return self._default_forest_params
    
    def generate_forest_task(
        self,
        participant: Participant = None,
        forest_param: ForestParameters = None,
        data_date_start: datetime = timezone.now(),    # generated once at import time. will differ,
        data_date_end: datetime = timezone.now(),      # slightly, but end is always after start.
        forest_tree: str = ForestTree.jasmine,
        **kwargs
    ):
        task = ForestTask(
            participant=participant or self.default_participant,
            forest_param=forest_param or self.default_forest_params,
            data_date_start=data_date_start,
            data_date_end=data_date_end,
            forest_tree=forest_tree,
            status=ForestTaskStatus.queued,
            **kwargs
        )
        task.save()
        return task
    
    
    #
    ## ChunkRegistry
    #
    @property
    def default_chunkregistry(self) -> ChunkRegistry:
        # the default chunkrestry object is an identifiers instance, this is likely irrelevant.
        try:
            return self._default_chunkregistry
        except AttributeError:
            self._default_chunkregistry = self.generate_chunkregistry(
                self.session_study, self.default_participant, IDENTIFIERS
            )
            return self._default_chunkregistry
    
    def generate_chunkregistry(
        self,
        study: Study,
        participant: Participant,
        data_type: str,
        path: str = None,
        hash_value: str = None,
        time_bin: datetime = None,
        file_size: int = None,
        survey: Survey = None,
        is_chunkable: bool = False,
    ) -> ChunkRegistry:
        chunk_reg = ChunkRegistry(
            study=study,
            participant=participant,
            data_type=data_type,
            chunk_path=path or generate_easy_alphanumeric_string(),
            chunk_hash=hash_value or generate_easy_alphanumeric_string(),
            time_bin=time_bin or timezone.now(),
            file_size=file_size or 0,
            is_chunkable=is_chunkable,
            survey=survey,
        )
        chunk_reg.save()
        return chunk_reg
    
    @property
    def default_summary_statistic_daily(self):
        try:
            return self._default_summary_statistic_daily
        except AttributeError:
            # its empty, this is ok
            self._default_summary_statistic_daily = self.generate_summary_statistic_daily()
            return self._default_summary_statistic_daily
    
    
    def default_summary_statistic_daily_cheatsheet(self):
        # this is used to populate default values in a SummaryStatisticDaily
        field_dict = {}
        for i, field in enumerate(SummaryStatisticDaily._meta.fields):
            if isinstance(field, (ForeignKey, DateField, AutoField)):
                continue
            elif isinstance(field, IntegerField):
                field_dict[field.name] = i
            elif isinstance(field, FloatField):
                field_dict[field.name] = float(i)
            elif isinstance(field, (TextField, CharField)):
                field_dict[field.name] = str(i)
            else:
                raise TypeError(f"encountered unhandled SummaryStatisticDaily type: {type(field)}")
        return field_dict
    
    def generate_summary_statistic_daily(self, a_date: date = None, participant: Participant = None):
        field_dict = self.default_summary_statistic_daily_cheatsheet()
        params = {}
        for field in SummaryStatisticDaily._meta.fields:
            if field.name in ["id", "created_on", "last_updated", "jasmine_task", "willow_task", "sycamore_task"]:
                continue
            elif field.name == "participant":
                params[field.name] = participant or self.default_participant
            elif field.name == "date":
                params[field.name] = a_date or date.today()
            else:
                params[field.name] = field_dict[field.name]
        stats = SummaryStatisticDaily(**params)
        stats.save()
        return stats


def compare_dictionaries(reference, comparee, ignore=None):
    """ Compares two dictionary objects and displays the differences in a useful fashion. """
    
    if not isinstance(reference, dict):
        raise Exception("reference was %s, not dictionary" % type(reference))
    if not isinstance(comparee, dict):
        raise Exception("comparee was %s, not dictionary" % type(comparee))
    
    if ignore is None:
        ignore = []
    
    b = set((x, y) for x, y in comparee.items() if x not in ignore)
    a = set((x, y) for x, y in reference.items() if x not in ignore)
    differences_a = a - b
    differences_b = b - a
    
    if len(differences_a) == 0 and len(differences_b) == 0:
        return True
    
    try:
        differences_a = sorted(differences_a)
        differences_b = sorted(differences_b)
    except Exception:
        pass
    
    print("These dictionaries are not identical:")
    if differences_a:
        print("in reference, not in comparee:")
        for x, y in differences_a:
            print("\t", x, y)
    if differences_b:
        print("in comparee, not in reference:")
        for x, y in differences_b:
            print("\t", x, y)
    
    return False


class DummyThreadPool():
    """ a dummy threadpool object because the test suite has weird problems with ThreadPool """
    def __init__(self, *args, **kwargs) -> None:
        pass
    
    # @staticmethod
    def imap_unordered(self, func, iterable, **kwargs):
        # we actually want to cut off any threadpool args, which is conveniently easy because map
        # does not use kwargs
        return map(func, iterable)
    
    # @staticmethod
    def terminate(self):
        pass
    
    # @staticmethod
    def close(self):
        pass


def render_test_html_file(response: HttpResponse, url: str):
    print("\nwriting url:", url)
    
    with open(CURRENT_TEST_HTML_FILEPATH, "wb") as f:
        f.write(response.content.replace(b"/static/", ABS_STATIC_ROOT))
    
    subprocess.check_call(["google-chrome", CURRENT_TEST_HTML_FILEPATH])
    x = input(f"opening {url} rendered html, press enter to continue test(s) or anything else to exit.")
    if x:
        exit()
