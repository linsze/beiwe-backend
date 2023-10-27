from datetime import timedelta
from unittest.mock import MagicMock, patch

import time_machine
from dateutil.tz import gettz
from django.utils import timezone

from constants.testing_constants import (THURS_OCT_6_NOON_2022_NY, THURS_OCT_13_NOON_2022_NY,
    THURS_OCT_20_NOON_2022_NY)
from database.schedule_models import ScheduledEvent
from services.celery_push_notifications import get_surveys_and_schedules
from tests.common import CommonTestCase


class TestCelery(CommonTestCase):
    pass


class TestGetSurveysAndSchedules(TestCelery):
    
    def test_empty_db(self):
        self.assertEqual(ScheduledEvent.objects.count(), 0)
        self.validate_no_schedules()
    
    def validate_no_schedules(self):
        surveys, schedules, patient_ids = get_surveys_and_schedules(timezone.now())
        self.assertEqual(surveys, {})
        self.assertEqual(schedules, {})
        self.assertEqual(patient_ids, {})
    
    def validate_basics(self, schedule: ScheduledEvent):
        surveys, schedules, patient_ids = get_surveys_and_schedules(timezone.now())
        self.assertEqual(surveys, {self.DEFAULT_FCM_TOKEN: [self.DEFAULT_SURVEY_OBJECT_ID]})
        self.assertEqual(schedules, {self.DEFAULT_FCM_TOKEN: [schedule.pk]})
        self.assertEqual(patient_ids, {self.DEFAULT_FCM_TOKEN: self.DEFAULT_PARTICIPANT_NAME})
    
    # just a placeholder for future work, send_notification not actually called in this test
    @patch('services.celery_push_notifications.send_notification')
    def test_absolute_success(self, send_notification: MagicMock):
        send_notification.return_value = None
        
        self.populate_default_fcm_token
        the_past = timezone.now() + timedelta(days=-5)
        # an absolute survey 5 days in the past
        schedule = self.generate_easy_absolute_schedule_event_with_schedule(the_past)
        self.validate_basics(schedule)
    
    def test_absolute_fail(self):
        self.populate_default_fcm_token
        future = timezone.now() + timedelta(days=5)
        # an absolute survey 5 days in the future
        self.generate_easy_absolute_schedule_event_with_schedule(future)
        self.validate_no_schedules()
    
    def test_relative_success(self):
        self.populate_default_fcm_token
        # a relative survey 5 days in the past
        schedule = self.generate_easy_relative_schedule_event_with_schedule(timedelta(days=-5))
        surveys, schedules, patient_ids = get_surveys_and_schedules(timezone.now())
        self.validate_basics(schedule)
    
    def test_relative_failure(self):
        self.populate_default_fcm_token
        # a relative survey 5 days in the past
        self.generate_easy_relative_schedule_event_with_schedule(timedelta(days=5))
        self.validate_no_schedules()
    
    @time_machine.travel(THURS_OCT_6_NOON_2022_NY)
    def test_weekly_success(self):
        self.populate_default_fcm_token
        # TODO: why is this passing
        # a weekly survey, on a friday, sunday is the zero-index; I hate it more than you.
        schedule, count_created = self.generate_a_real_weekly_schedule_event_with_schedule(5)
        self.assertEqual(count_created, 1)
        with time_machine.travel(THURS_OCT_20_NOON_2022_NY):
            self.validate_basics(schedule)
    
    @time_machine.travel(THURS_OCT_6_NOON_2022_NY)
    def test_weekly_in_future_fails(self):
        self.populate_default_fcm_token
        # TODO: why is this passing
        # a weekly survey, on a friday, sunday is the zero-index; I hate it more than you.
        schedule, count_created = self.generate_a_real_weekly_schedule_event_with_schedule(5)
        self.assertEqual(count_created, 1)
        self.validate_no_schedules()
    
    @time_machine.travel(THURS_OCT_13_NOON_2022_NY)
    def test_time_zones(self):
        self.populate_default_fcm_token
        self.default_study.update_only(timezone_name='America/New_York')  # default in tests is normally UTC.
        
        # need to time travel to the past to get the weekly logic to produce the correct time
        with time_machine.travel(THURS_OCT_6_NOON_2022_NY):
            # creates a weekly survey for 2022-10-13 12:00:00-04:00
            schedule, count_created = self.generate_a_real_weekly_schedule_event_with_schedule(4, 12, 0)
            self.assertEqual(count_created, 1)
        
        # assert schedule time is equal to 2022-10-13 12:00:00-04:00, then assert components are equal.
        self.assertEqual(schedule.scheduled_time, THURS_OCT_13_NOON_2022_NY)
        self.assertEqual(schedule.scheduled_time.year, 2022)
        self.assertEqual(schedule.scheduled_time.month, 10)
        self.assertEqual(schedule.scheduled_time.day, 13)
        self.assertEqual(schedule.scheduled_time.hour, 12)
        self.assertEqual(schedule.scheduled_time.minute, 0)
        self.assertEqual(schedule.scheduled_time.second, 0)
        self.assertEqual(schedule.scheduled_time.tzinfo, gettz("America/New_York"))
        
        # set default participant to pacific time, assert that no push notification is calculated.
        self.default_participant.try_set_timezone('America/Los_Angeles')
        self.validate_no_schedules()
        
        # set the time zone to mountain time, assert that no push notification is calculated.
        self.default_participant.try_set_timezone('America/Denver')
        self.validate_no_schedules()
        
        # set the time zone to central time, assert that no push notification is calculated.
        self.default_participant.try_set_timezone('America/Chicago')
        self.validate_no_schedules()
        
        # but if you set the time zone to New_York the push notification is calculated!
        self.default_participant.try_set_timezone('America/New_York')
        self.validate_basics(schedule)
