from datetime import date, datetime, timedelta
from typing import List, Tuple

from constants.schedule_constants import EMPTY_WEEKLY_SURVEY_TIMINGS
from database.schedule_models import AbsoluteSchedule, ArchivedEvent, ScheduledEvent, WeeklySchedule
from database.study_models import Study
from database.survey_models import Survey
from database.user_models_participant import Participant
from libs.utils.date_utils import date_to_end_of_day, date_to_start_of_day


class NoSchedulesException(Exception): pass
class UnknownScheduleScenario(Exception): pass


# Weekly timings lists code
def get_start_and_end_of_java_timings_week(now: datetime) -> Tuple[datetime, datetime]:
    """ study timezone aware week start and end """
    if now.tzinfo is None:
        raise TypeError("missing required timezone-aware datetime")
    now_date: date = now.date()
    date_sunday_start_of_week = now_date - timedelta(days=now.weekday() + 1)
    date_saturday_end_of_week = now_date + timedelta(days=5 - now.weekday())  # TODO: Test
    dt_sunday_start_of_week = date_to_start_of_day(date_sunday_start_of_week, now.tzinfo)
    dt_saturday_end_of_week = date_to_end_of_day(date_saturday_end_of_week, now.tzinfo)
    return dt_sunday_start_of_week, dt_saturday_end_of_week


def decompose_datetime_to_timings(dt: datetime) -> Tuple[int, int]:
    """ returns day-index, seconds into day. """
    # have to convert to sunday-zero-indoexed
    return (dt.weekday() + 1) % 7, dt.hour * 60 * 60 + dt.minute * 60


#
# Event scheduling
#
def set_next_weekly(participant: Participant, survey: Survey) -> Tuple[ScheduledEvent, int]:
    ''' Create a next ScheduledEvent for a survey for a particular participant. Uses get_or_create. '''
    schedule_date, schedule = get_next_weekly_event_and_schedule(survey)
    
    # this handles the case where the schedule was deleted. This is a corner case that shouldn't happen
    if schedule_date is not None and schedule is not None:
        # Return so we can write tests easier, its fine
        return ScheduledEvent.objects.get_or_create(
            survey=survey,
            participant=participant,
            weekly_schedule=schedule,
            relative_schedule=None,
            absolute_schedule=None,
            scheduled_time=schedule_date,
        )
    else:
        raise UnknownScheduleScenario("unknown condition reached")


def repopulate_all_survey_scheduled_events(study: Study, participant: Participant = None):
    """ Runs all the survey scheduled event generations on the provided entities. """
    for survey in study.surveys.all():
        # remove any scheduled events on surveys that have been deleted.
        if survey.deleted:
            survey.scheduled_events.all().delete()
            continue
        
        repopulate_weekly_survey_schedule_events(survey, participant)
        repopulate_absolute_survey_schedule_events(survey, participant)
        # there are some cases where we can logically exclude relative surveys.
        # Don't. Do. That. Just. Run. Everything. Always.
        repopulate_relative_survey_schedule_events(survey, participant)


#TODO: this will need to be rewritten to examine existing weekly schedules
def repopulate_weekly_survey_schedule_events(survey: Survey, single_participant: Participant = None) -> None:
    """ Clear existing schedules, get participants, bulk create schedules Weekly events are
    calculated in a way that we don't bother checking for survey archives, because they only exist
    in the future. """
    events = survey.scheduled_events.filter(relative_schedule=None, absolute_schedule=None)
    if single_participant:
        events = events.filter(participant=single_participant)
        participant_ids = [single_participant.pk]
    else:
        participant_ids = survey.study.participants.exclude(deleted=True).values_list("pk", flat=True)
    
    events.delete()
    if single_participant and single_participant.deleted:
        return
    
    try:
        # get_next_weekly_event forces tz-aware schedule_date datetime object
        schedule_date, schedule = get_next_weekly_event_and_schedule(survey)
    except NoSchedulesException:
        return
    
    ScheduledEvent.objects.bulk_create(
        [
            ScheduledEvent(
                survey=survey,
                participant_id=participant_id,
                weekly_schedule=schedule,
                relative_schedule=None,
                absolute_schedule=None,
                scheduled_time=schedule_date,
            ) for participant_id in participant_ids
        ]
    )


#TODO: this will need to be rewritten to examine existing absolute schedules
def repopulate_absolute_survey_schedule_events(survey: Survey, single_participant: Participant = None) -> None:
    """ Creates new ScheduledEvents for the survey's AbsoluteSchedules while deleting the old
    ScheduledEvents related to the survey """
    # if the event is from an absolute schedule, relative and weekly schedules will be None
    events = survey.scheduled_events.filter(relative_schedule=None, weekly_schedule=None)
    if single_participant:
        events = events.filter(participant=single_participant)
    events.delete()
    
    if single_participant and single_participant.deleted:
        return
    
    new_events = []
    abs_sched: AbsoluteSchedule
    # for each absolute schedule on the survey create a new scheduled event for each participant.
    for abs_sched in survey.absolute_schedules.all():
        scheduled_time = abs_sched.event_time
        # if one participant
        if single_participant:
            archive_exists = ArchivedEvent.objects.filter(
                survey_archive__survey=survey,
                scheduled_time=scheduled_time,
                participant_id=single_participant.pk
            ).exists()
            relevant_participants = [] if archive_exists else [single_participant.pk]
        
        # if many participants
        else:
            # don't create events for already sent notifications, or deleted participants
            irrelevant_participants = ArchivedEvent.objects.filter(
                survey_archive__survey=survey, scheduled_time=scheduled_time,
            ).values_list("participant_id", flat=True)
            relevant_participants = survey.study.participants.exclude(
                pk__in=irrelevant_participants, deleted=True
            ).values_list("pk", flat=True)
        
        # populate the new events
        for participant_id in relevant_participants:
            new_events.append(ScheduledEvent(
                survey=survey,
                weekly_schedule=None,
                relative_schedule=None,
                absolute_schedule_id=abs_sched.pk,
                scheduled_time=scheduled_time,
                participant_id=participant_id
            ))
    # save to database
    ScheduledEvent.objects.bulk_create(new_events)


def repopulate_relative_survey_schedule_events(survey: Survey, single_participant: Participant = None) -> None:
    """ Creates new ScheduledEvents for the survey's RelativeSchedules while deleting the old
    ScheduledEvents related to the survey. """
    # Clear out existing events.
    events = survey.scheduled_events.filter(absolute_schedule=None, weekly_schedule=None)
    if single_participant:
        events = events.filter(participant=single_participant)
    events.delete()
    
    if single_participant and single_participant.deleted:
        return
    
    # This is per schedule, and a participant can't have more than one intervention date per
    # intervention per schedule.  It is also per survey and all we really care about is
    # whether an event ever triggered on that survey.
    new_events = []
    study_timezone = survey.study.timezone  # might as well cache this...
    for relative_schedule in survey.relative_schedules.all():
        # Only interventions that have been marked (have a date), for participants that are not
        # deleted, restrict on the single user case, get data points.
        intervention_dates_query = relative_schedule.intervention.intervention_dates.filter(
            date__isnull=False,
            participant__deleted=False  # do not refactor to .exclude!
            # Subtle [Django?] Bug that I don't understand: you can't exclude null database values?
            #   intervention_dates_query.exclude(date__isnull=True, ...)
            #  The above query.exclude returns instances where date is None, same for `date=None`
        )
        if single_participant:
            intervention_dates_query = intervention_dates_query.filter(participant=single_participant)
        intervention_dates_query = intervention_dates_query.values_list("participant_id", "date")
        
        for participant_id, intervention_date in intervention_dates_query:
            # + below is correct, 'days_after' is negative or 0 for days before and day of.
            # bug: somehow got a Nonetype error even though intervention_date cannot be None... how?
            # "unsupported operand type(s) for +: 'NoneType' and 'datetime.timedelta'"
            # (the order of items in the error statements reflects the code, so intervention_date was None.)
            scheduled_date = intervention_date + timedelta(days=relative_schedule.days_after)
            schedule_time = relative_schedule.scheduled_time(scheduled_date, study_timezone)
            # skip if already sent (archived event matching participant, survey, and schedule time)
            if ArchivedEvent.objects.filter(
                participant_id=participant_id,
                survey_archive__survey_id=survey.id,
                scheduled_time=schedule_time,
            ).exists():
                continue
            
            new_events.append(ScheduledEvent(
                survey=survey,
                participant_id=participant_id,
                weekly_schedule=None,
                relative_schedule=relative_schedule,
                absolute_schedule=None,
                scheduled_time=schedule_time,
            ))
    
    ScheduledEvent.objects.bulk_create(new_events)


def get_next_weekly_event_and_schedule(survey: Survey) -> Tuple[datetime, WeeklySchedule]:
    """ Determines the next time for a particular survey, provides the relevant weekly schedule. """
    now = survey.study.now()
    timings_list = []
    # our possible next weekly event may be this week, or next week; get this week if it hasn't
    # happened, next week if it has.  A survey can have many weekly schedules, grab them all.
    
    for weekly_schedule in survey.weekly_schedules.all():
        this_week, next_week = weekly_schedule.get_prior_and_next_event_times(now)
        timings_list.append((this_week if now < this_week else next_week, weekly_schedule))
    
    if not timings_list:
        raise NoSchedulesException()
    
    # get the earliest next schedule_date
    timings_list.sort(key=lambda date_and_schedule: date_and_schedule[0])
    schedule_datetime, schedule = timings_list[0]
    return schedule_datetime, schedule


def export_weekly_survey_timings(survey: Survey) -> List[List[int]]:
    """Returns a json formatted list of weekly timings for use on the frontend"""
    # this weird sort order results in correctly ordered output.
    fields_ordered = ("hour", "minute", "day_of_week")
    timings = EMPTY_WEEKLY_SURVEY_TIMINGS()
    schedule_components = WeeklySchedule.objects. \
        filter(survey=survey).order_by(*fields_ordered).values_list(*fields_ordered)
    
    # get, calculate, append, dump.
    for hour, minute, day in schedule_components:
        timings[day].append((hour * 60 * 60) + (minute * 60))
    return timings
