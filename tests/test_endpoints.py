import json
from copy import copy
from datetime import date, datetime, timedelta
from io import BytesIO
from typing import List
from unittest.mock import MagicMock, patch

import time_machine
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import SimpleUploadedFile
from django.db import models
from django.forms.fields import NullBooleanField
from django.http.response import FileResponse, HttpResponse, HttpResponseRedirect
from django.urls import reverse
from django.utils import timezone

from api.tableau_api import FINAL_SERIALIZABLE_FIELDS
from config.jinja2 import easy_url
from constants.celery_constants import (ANDROID_FIREBASE_CREDENTIALS, BACKEND_FIREBASE_CREDENTIALS,
    IOS_FIREBASE_CREDENTIALS)
from constants.common_constants import API_DATE_FORMAT, BEIWE_PROJECT_ROOT
from constants.dashboard_constants import COMPLETE_DATA_STREAM_DICT, DASHBOARD_DATA_STREAMS
from constants.data_stream_constants import ACCELEROMETER, ALL_DATA_STREAMS, SURVEY_TIMINGS
from constants.message_strings import (DEVICE_HAS_NO_REGISTERED_TOKEN, MESSAGE_SEND_FAILED_UNKNOWN,
    MESSAGE_SEND_SUCCESS, MFA_CODE_6_DIGITS, MFA_CODE_DIGITS_ONLY, MFA_CODE_MISSING, MFA_CODE_WRONG,
    MFA_CONFIGURATION_REQUIRED, MFA_CONFIGURATION_SITE_ADMIN, MFA_RESET_BAD_PERMISSIONS,
    MFA_SELF_BAD_PASSWORD, MFA_SELF_DISABLED, MFA_SELF_NO_PASSWORD, MFA_SELF_SUCCESS,
    MFA_TEST_DISABLED, MFA_TEST_FAIL, MFA_TEST_SUCCESS, NEW_PASSWORD_MISMATCH, NEW_PASSWORD_N_LONG,
    NEW_PASSWORD_RULES_FAIL, NO_DELETION_PERMISSION, PARTICIPANT_LOCKED, PASSWORD_EXPIRED,
    PASSWORD_RESET_FAIL_SITE_ADMIN, PASSWORD_RESET_FORCED, PASSWORD_RESET_SITE_ADMIN,
    PASSWORD_RESET_SUCCESS, PASSWORD_RESET_TOO_SHORT, PASSWORD_WILL_EXPIRE,
    PUSH_NOTIFICATIONS_NOT_CONFIGURED, TABLEAU_API_KEY_IS_DISABLED, TABLEAU_NO_MATCHING_API_KEY,
    WRONG_CURRENT_PASSWORD)
from constants.schedule_constants import EMPTY_WEEKLY_SURVEY_TIMINGS
from constants.security_constants import MFA_CREATED
from constants.testing_constants import (ADMIN_ROLES, ALL_TESTING_ROLES, ANDROID_CERT, BACKEND_CERT,
    IOS_CERT, MIDNIGHT_EVERY_DAY, THURS_OCT_6_NOON_2022_NY)
from constants.url_constants import LOGIN_REDIRECT_SAFE, urlpatterns
from constants.user_constants import ALL_RESEARCHER_TYPES, IOS_API, ResearcherRole
from database.data_access_models import ChunkRegistry, FileToProcess
from database.profiling_models import DataAccessRecord
from database.schedule_models import (AbsoluteSchedule, ArchivedEvent, Intervention, ScheduledEvent,
    WeeklySchedule)
from database.security_models import ApiKey
from database.study_models import DeviceSettings, Study, StudyField
from database.survey_models import Survey
from database.system_models import FileAsText, GenericEvent
from database.user_models_participant import (Participant, ParticipantDeletionEvent,
    ParticipantFCMHistory)
from database.user_models_researcher import Researcher, StudyRelation
from libs.copy_study import format_study
from libs.rsa import get_RSA_cipher
from libs.schedules import (get_start_and_end_of_java_timings_week,
    repopulate_absolute_survey_schedule_events, repopulate_relative_survey_schedule_events)
from libs.security import device_hash, generate_easy_alphanumeric_string
from tests.common import (BasicSessionTestCase, CommonTestCase, DataApiTest, ParticipantSessionTest,
    ResearcherSessionTest, SmartRequestsTestCase)
from tests.helpers import DummyThreadPool


#
## login_pages
#

class TestLoginPages(BasicSessionTestCase):
    """ Basic authentication test, make sure that the machinery for logging a user
    in and out are functional at setting and clearing a session. 
    THIS CLASS DOES NOT AUTO INSTANTIATE THE DEFAULT RESEARCHER, YOU MUST DO THAT MANUALLY. """
    
    THE_PAST = datetime(2010, 1, 1, tzinfo=timezone.utc)
    
    def test_load_login_page_while_not_logged_in(self):
        # make sure the login page loads without logging you in when it should not
        response = self.client.get(reverse("login_pages.login_page"))
        self.assertEqual(response.status_code, 200)
        # this should uniquely identify the login page
        self.assertIn(b'<form method="POST" action="/validate_login">', response.content)
    
    def test_load_login_page_while_logged_in(self):
        # make sure the login page loads without logging you in when it should not
        self.session_researcher  # create the default researcher
        self.do_default_login()
        response = self.client.get(reverse("login_pages.login_page"))
        self.assertEqual(response.status_code, 302)
        self.assert_response_url_equal(response.url, reverse("admin_pages.choose_study"))
        # this should uniquely identify the login page
        self.assertNotIn(b'<form method="POST" action="/validate_login">', response.content)
    
    def test_logging_in_success(self):
        self.session_researcher  # create the default researcher
        r = self.do_default_login()
        self.assertEqual(r.status_code, 302)
        self.assert_response_url_equal(r.url, reverse("admin_pages.choose_study"))
    
    def test_logging_in_fail(self):
        r = self.do_default_login()
        self.assertEqual(r.status_code, 302)
        self.assert_response_url_equal(r.url, reverse("login_pages.login_page"))
    
    def test_logging_out(self):
        # create the default researcher, login, logout, attempt going to main page,
        self.session_researcher
        self.do_default_login()
        self.client.get(reverse("admin_pages.logout_admin"))
        r = self.client.get(reverse("admin_pages.choose_study"))
        self.assertEqual(r.status_code, 302)
        self.assert_response_url_equal(r.url, reverse("login_pages.login_page"))
    
    # tests for different combinations of conditions to redirect someone to the password reset page
    # when a condition has been matched
    def test_password_reset_forced_empty_researcher(self):
        self.session_researcher.update(password_force_reset=True)
        self._test_password_reset_redirect_logic(PASSWORD_RESET_FORCED)
    
    def test_password_reset_forced_researcher_with_relation_no_details(self):
        self.session_researcher.update(password_force_reset=True)
        self.set_session_study_relation(ResearcherRole.researcher)
        self._test_password_reset_redirect_logic(PASSWORD_RESET_FORCED)
    
    def test_password_reset_forced_study_admin_with_relation_no_details(self):
        self.session_researcher.update(password_force_reset=True)
        self.set_session_study_relation(ResearcherRole.study_admin)
        self._test_password_reset_redirect_logic(PASSWORD_RESET_FORCED)
    
    def test_password_reset_forced_site_admin_with_relation_no_details(self):
        self.session_researcher.update(password_force_reset=True)
        self.set_session_study_relation(ResearcherRole.site_admin)
        self._test_password_reset_redirect_logic(PASSWORD_RESET_FORCED)
    
    def test_password_reset_forced_empty_researcher_2_studies(self):
        self.session_researcher.update(password_force_reset=True)
        self.generate_study("study 1")
        self.generate_study("study 2")
        self._test_password_reset_redirect_logic(PASSWORD_RESET_FORCED)
    
    def test_password_reset_forced_researcher_with_relation_no_details_2_studies(self):
        self.session_researcher.update(password_force_reset=True)
        self.set_session_study_relation(ResearcherRole.researcher)
        study2 = self.generate_study("study 2")
        self.generate_study_relation(self.session_researcher, study2, ResearcherRole.researcher)
        self._test_password_reset_redirect_logic(PASSWORD_RESET_FORCED)
    
    def test_password_reset_forced_study_admin_with_relation_no_details_2_studies(self):
        self.session_researcher.update(password_force_reset=True)
        self.set_session_study_relation(ResearcherRole.study_admin)
        study2 = self.generate_study("study 2")
        self.generate_study_relation(self.session_researcher, study2, ResearcherRole.study_admin)
        self._test_password_reset_redirect_logic(PASSWORD_RESET_FORCED)
    
    def test_password_reset_forced_site_admin_with_relation_no_details_2_studies(self):
        self.session_researcher.update(password_force_reset=True)
        self.set_session_study_relation(ResearcherRole.site_admin)
        self.generate_study("study 2")
        self._test_password_reset_redirect_logic(PASSWORD_RESET_FORCED)
    
    def test_password_expired(self):
        # test that there is a study with an expiration, and the password is expired
        self.session_researcher.update(password_last_changed=timezone.now() - timedelta(days=40))
        self.set_session_study_relation(ResearcherRole.researcher)
        self.session_study.update(password_max_age_enabled=True, password_max_age_days=30),
        self._test_password_reset_redirect_logic(PASSWORD_EXPIRED)
    
    def _test_password_reset_redirect_logic(self, error_message: str):
        # password reset redirects initially to the choose study page, then to the manage credentials page
        response = self.do_default_login()
        self.assert_response_url_equal(response.url, reverse("admin_pages.choose_study"))
        response2 = self.client.get(response.url)
        self.assert_response_url_equal(response2.url, reverse("admin_pages.manage_credentials"))
        response3 = self.client.get(reverse("admin_pages.manage_credentials"))
        self.assertEqual(response3.status_code, 200)
        self.assert_present(error_message, response3.content)
    
    def test_password_not_even_expired(self):
        # test that there is not even a study with an expiration
        self.session_researcher.update(password_last_changed=self.THE_PAST)
        self.set_session_study_relation(ResearcherRole.researcher)
        self.session_study.update(password_max_age_enabled=False)  # its already false
        self._test_password_not_expired()
    
    def test_password_not_expired(self):
        # test that there is a study with an expiration, but the password is not expired
        self.session_researcher.update(password_last_changed=timezone.now() - timedelta(days=20))
        self.set_session_study_relation(ResearcherRole.researcher)
        self.session_study.update(password_max_age_enabled=True, password_max_age_days=30),
        self._test_password_not_expired()
    
    def test_password_almost_expired(self):
        # test that there is a study with an expiration, and the password is expired
        self.session_researcher.update(password_last_changed=timezone.now() - timedelta(days=25))
        self.set_session_study_relation(ResearcherRole.researcher)
        self.session_study.update(password_max_age_enabled=True, password_max_age_days=30),
        self._test_password_almost_expired()
    
    def test_password_almost_expired_2(self):
        # as above but with 2 studies with different password max age settings, get the lowest.
        self.session_researcher.update(password_last_changed=timezone.now() - timedelta(days=25))
        self.set_session_study_relation(ResearcherRole.researcher)
        self.session_study.update(password_max_age_enabled=True, password_max_age_days=40)
        study2 = self.generate_study("study 2")
        study2.update(password_max_age_enabled=True, password_max_age_days=30)
        self.generate_study_relation(self.session_researcher, study2, ResearcherRole.researcher)
        # ug this one bypasses all the special logic I put together and just loads the choose study
        # page with the message.
        response = self.do_default_login()
        self.assert_response_url_equal(response.url, reverse("admin_pages.choose_study"))
        response2 = self.client.get(response.url)
        self.assertEqual(response2.status_code, 200)
        self.assert_present(PASSWORD_WILL_EXPIRE.format(days=5), response2.content)
        self.assert_not_present(PASSWORD_EXPIRED, response2.content)
        self.assert_not_present(PASSWORD_RESET_FORCED, response2.content)
    
    def _test_password_almost_expired(self):
        # this one redirects initially to choose study page,then to the view study page with a message.
        # expects a password to expire in 5 days
        response2 = self._test_initial_redirect()
        response3 = self.client.get(response2.url)
        self.assertEqual(response3.status_code, 200)
        self.assert_present(PASSWORD_WILL_EXPIRE.format(days=5), response3.content)
        self.assert_not_present(PASSWORD_EXPIRED, response3.content)
        self.assert_not_present(PASSWORD_RESET_FORCED, response3.content)
    
    def _test_password_not_expired(self):
        # password reset redirects initially to the choose study page, then to the view study page
        response2 = self._test_initial_redirect()
        response3 = self.client.get(response2.url)
        self.assertEqual(response3.status_code, 200)
        # none of the password messages should be visible
        self.assert_not_present(PASSWORD_WILL_EXPIRE, response3.content)
        self.assert_not_present(PASSWORD_EXPIRED, response3.content)
        self.assert_not_present(PASSWORD_RESET_FORCED, response3.content)
    
    def _test_initial_redirect(self):
        # these tests are a distraction from the details of tests that run other logic, but it
        # still needs to be tested.  Most of the complexity is in determine_2nd_redirect
        response = self.do_default_login()
        self.assert_response_url_equal(response.url, reverse("admin_pages.choose_study"))
        response2 = self.client.get(response.url)
        # its not always a redirect, sometimes it actually loads the page, but if it is a redirect
        # we run the logic to test it.
        self.assert_response_url_equal(response2.url, self.determine_2nd_redirect)
        return response2
    
    @property
    def determine_2nd_redirect(self):
        # when there is 1 study redirect to that view study page, otherwise show the choose study
        # page (the login page always says redirect to choose_study, the logic to then redirect is
        # part of the choose study endpoint)
        # 2 cases: site admin, or not site admin
        if self.session_researcher.site_admin:
            if Study.objects.count() == 1:
                return easy_url("admin_pages.view_study", study_id=self.session_study.id)
            else:
                return reverse("admin_pages.choose_study")
        if self.session_researcher.study_relations.count() == 1:
            return easy_url("admin_pages.view_study", study_id=self.session_study.id)
        else:
            return reverse("admin_pages.choose_study")
    
    def test_password_redirect_ignored_endpoint_manage_credentials(self):
        # test that the password redirect is ignored for manage credentials page
        self.session_researcher
        self.do_default_login()
        self.session_researcher.update(password_force_reset=True)
        resp = self.client.get(reverse("admin_pages.manage_credentials"))
        self.assertIsInstance(resp, HttpResponse)
        self.assertEqual(resp.status_code, 200)
    
    def test_password_redirect_ignored_endpoint_logout(self):
        # test that the password redirect is ignored logout endpoint
        self.session_researcher
        self.do_default_login()
        self.session_researcher.update(password_force_reset=True)
        resp = self.client.get(reverse("admin_pages.logout_admin"))
        self.assertIsInstance(resp, HttpResponseRedirect)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, reverse("login_pages.login_page"))  # that's the / endpoint
    
    def test_password_redirect_ignored_endpoint_reset_password(self):
        # test that the password redirect is ignored for the set password endpoint
        self.session_researcher
        self.do_default_login()
        self.session_researcher.update(password_force_reset=True)
        resp = self.client.post(reverse("admin_pages.reset_admin_password"))
        self.assertIsInstance(resp, HttpResponse)
        self.assertEqual(resp.status_code, 400)
    
    def test_admin_decorator(self):
        # We don't have an integration test for determine_password_reset_redirect, this is kind of a
        # proxy test that the already-tested logic of the password reset logic is included in the
        # authenticate_admin decorator
        self.session_researcher.update(password_force_reset=True)
        self.set_session_study_relation(ResearcherRole.site_admin)
        self.do_default_login()
        name = self.session_study.name
        resp = self.client.post(easy_url("admin_api.rename_study", study_id=self.session_study.id))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, reverse("admin_pages.manage_credentials"))
        self.session_study.refresh_from_db()
        self.assertEqual(self.session_study.name, name)  # assert name didn't change
    
    def test_session_expiry(self):
        # set up the current time, then we will travel into the future to test the session expiry
        # in a loop, hour by hour, testing that we redirect to the login page after 18 hours
        self.session_researcher
        start = datetime.now()
        check_1_happened = False
        check_2_happened = False
        for hour in range(0, 24):
            self.do_default_login()
            # the +1 minute ensures we are passing the hour mark
            with time_machine.travel(start + timedelta(hours=hour, minutes=1)):
                if hour < 18:
                    resp = self.client.get(reverse("admin_pages.choose_study"))
                    self.assertEqual(resp.status_code, 200)
                    check_1_happened = True
                else:
                    resp = self.client.get(reverse("admin_pages.choose_study"))
                    self.assertEqual(resp.status_code, 302)
                    self.assertEqual(resp.url, reverse("login_pages.login_page"))
                    check_2_happened = True
        # make sure we actually tested both cases
        self.assertTrue(check_1_happened)
        self.assertTrue(check_2_happened)
    
    def test_password_too_short_site_admin(self):
        # test that the password too short redirect applies to admin endpoints
        self.assertEquals(self.session_researcher.password_min_length, len(self.DEFAULT_RESEARCHER_PASSWORD))
        self.session_researcher.update_only(password_min_length=8)
        self.set_session_study_relation(ResearcherRole.site_admin)
        self.do_default_login()
        # random endpoint that will trigger a redirect
        resp = self.client.post(easy_url("admin_api.rename_study", study_id=self.session_study.id))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, reverse("admin_pages.manage_credentials"))
        page = self.simple_get(resp.url, status_code=200).content
        self.assert_present(PASSWORD_RESET_SITE_ADMIN, page)
        # assert that this behavior does not rely on the force reset flag
        self.assertFalse(self.session_researcher.password_force_reset)
    
    def test_password_too_short_researcher(self):
        # test that the password too short redirect applies to admin endpoints
        self.assertEquals(self.session_researcher.password_min_length, len(self.DEFAULT_RESEARCHER_PASSWORD))
        self.session_study.update_only(password_minimum_length=20)
        self.session_researcher.update_only(password_min_length=8)
        self.set_session_study_relation(ResearcherRole.researcher)
        self.do_default_login()
        # random endpoint that will trigger a redirect
        resp = self.simple_get(easy_url("admin_pages.choose_study"))
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, reverse("admin_pages.manage_credentials"))
        page = self.simple_get(resp.url, status_code=200).content
        self.assert_present(PASSWORD_RESET_TOO_SHORT, page)
        # assert that this behavior does not rely on the force reset flag
        self.assertFalse(self.session_researcher.password_force_reset)
    
    def test_force_logout(self):
        self.session_researcher
        resp = self.do_default_login()
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(resp.url, reverse("admin_pages.choose_study"))
        self.simple_get(resp.url, status_code=200)  # page loads as normal
        self.session_researcher.force_global_logout()
        resp = self.simple_get(resp.url, status_code=302)  # page redirects to login
        self.session_researcher.refresh_from_db()
        self.assertEqual(self.session_researcher.web_sessions.count(), 0)
        self.assertEqual(resp.url, reverse("login_pages.login_page"))
    
    def test_mfa_login(self):
        self.session_researcher.reset_mfa()  # enable mfa
        if self.session_researcher._mfa_now == "123456":
            self.session_researcher.reset_mfa()  # ensure mfa code is not 123456
        
        r1 = self.do_default_login()
        self.assertEqual(r1.status_code, 302)  # assert login failure
        self.assertEqual(r1.url, "/")
        the_login_page = self.simple_get("/", status_code=200).content
        self.assert_present(MFA_CODE_MISSING, the_login_page)  # missing mfa
        self.do_login(self.DEFAULT_RESEARCHER_NAME, self.DEFAULT_RESEARCHER_PASSWORD, mfa_code="123456")  # wrong mfa code
        the_login_page = self.simple_get("/", status_code=200).content
        self.assert_present(MFA_CODE_WRONG, the_login_page)
        self.do_login(self.DEFAULT_RESEARCHER_NAME, self.DEFAULT_RESEARCHER_PASSWORD, mfa_code="1234567")  # too long mfa code
        the_login_page = self.simple_get("/", status_code=200).content
        self.assert_present(MFA_CODE_6_DIGITS, the_login_page)
        self.do_login(self.DEFAULT_RESEARCHER_NAME, self.DEFAULT_RESEARCHER_PASSWORD, mfa_code="abcdef")  # non-numeric mfa code
        the_login_page = self.simple_get("/", status_code=200).content
        self.assert_present(MFA_CODE_DIGITS_ONLY, the_login_page)
    
    def test_mfa_required(self):
        self.session_researcher
        self.do_default_login()
        self.default_study.update_only(mfa_required=True)  # enable mfa
        self.set_session_study_relation()  # ensure researcher is on study
        resp = self.simple_get(easy_url("admin_pages.choose_study"), status_code=302)  # page redirects
        self.assertEqual(resp.url, reverse("admin_pages.manage_credentials"))
        resp = self.simple_get(resp.url, status_code=200)  # page loads as normal
        self.assert_present(MFA_CONFIGURATION_REQUIRED, resp.content)
    
    @patch("authentication.admin_authentication.REQUIRE_SITE_ADMIN_MFA")
    @patch("database.user_models_researcher.REQUIRE_SITE_ADMIN_MFA")
    def test_mfa_required_site_admin_setting_only_affects_site_admins(self, patch1: MagicMock, patch2: MagicMock):
        patch1.return_value = True
        patch2.return_value = True
        self.session_researcher.update(mfa_token=None)
        r1 = self.do_default_login()
        self.assertEqual(r1.status_code, 302)  # assert login failure
        # it redirects to choose study, choose study loads
        self.assertEqual(r1.url, easy_url("admin_pages.choose_study"))
    
    @patch("authentication.admin_authentication.REQUIRE_SITE_ADMIN_MFA")
    @patch("database.user_models_researcher.REQUIRE_SITE_ADMIN_MFA")
    def test_mfa_required_site_admin_setting(self, patch1: MagicMock, patch2: MagicMock):
        patch1.return_value = True
        patch2.return_value = True
        self.session_researcher.update(mfa_token=None, site_admin=True)
        r1 = self.do_default_login()
        self.assertEqual(r1.status_code, 302)  # assert login failure
        # it redirects to choose study, then choose study should redirect to manage credentials
        self.assertEqual(r1.url, easy_url("admin_pages.choose_study"))
        r2 = self.simple_get(easy_url("admin_pages.choose_study"), status_code=302)  # page redirects
        self.assertEqual(r2.url, reverse("admin_pages.manage_credentials"))  # correct redirect
        r3 = self.simple_get(r2.url, status_code=200)  # page loads as normal
        self.assert_present(MFA_CONFIGURATION_REQUIRED, r3.content)
        self.assert_present(MFA_CONFIGURATION_SITE_ADMIN, r3.content)


class TestChooseStudy(ResearcherSessionTest):
    ENDPOINT_NAME = "admin_pages.choose_study"
    
    # these tests tost behavior of redirection without anything in the most_recent_page tracking
    # or as forwarding from the login page via the referrer url parameter into the post parameter
    
    def test_2_studies(self):
        study2 = self.generate_study("study2")
        self.set_session_study_relation(ResearcherRole.researcher)
        self.generate_study_relation(self.session_researcher, study2, ResearcherRole.researcher)
        resp = self.smart_get_status_code(200)
        self.assert_present(self.session_study.name, resp.content)
        self.assert_present(study2.name, resp.content)
    
    def test_1_study(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        resp = self.smart_get_status_code(302)
        self.assertEqual(resp.url, easy_url("admin_pages.view_study", study_id=self.session_study.id))
    
    def test_no_study(self):
        self.set_session_study_relation(None)
        resp = self.smart_get_status_code(200)
        self.assert_not_present(self.session_study.name, resp.content)


class TestResearcherRedirectionLogic(BasicSessionTestCase):
    # This needs to be comprehensive. It is checked for validity in one test and then used in the other.
    # This is a set because there are 2 entries for every endpoint, with and without slashes.
    LOCAL_COPY_WHITELIST = set([
        "admin_pages.view_study",
        "dashboard_api.dashboard_page",
        "dashboard_api.get_data_for_dashboard_datastream_display",
        "dashboard_api.dashboard_participant_page",
        "data_access_web_form.data_api_web_form_page",
        "forest_pages.analysis_progress",
        "forest_pages.task_log",
        "participant_pages.notification_history",
        "participant_pages.participant_page",
        "study_api.interventions_page",
        "study_api.study_fields",
        "survey_designer.render_edit_survey",
        "system_admin_pages.device_settings",
        "system_admin_pages.edit_researcher",
        "system_admin_pages.edit_study",
        "system_admin_pages.manage_firebase_credentials",
        "system_admin_pages.manage_researchers",
        "system_admin_pages.manage_studies",
        "system_admin_pages.study_security_page",
    ])
    
    @property
    def urls(self):
        # a list of ~valid test urls for every single url in LOGIN_REDIRECT_SAFE.
        # (these urls must start with a slash, ending slash shouldn't matter)
        return [
            f"/dashboard/{self.session_study.id}",
            f"/dashboard/{self.session_study.id}/patient/{self.default_participant.id}",
            f"/dashboard/{self.session_study.id}/data_stream/gps",
            "/data_access_web_form/",
            f"/device_settings/{self.session_study.id}",
            f"/edit_researcher/{self.session_researcher.id}",  # technically an invalid url on page load
            f"/edit_study/{self.session_study.id}",
            f"/edit_study_security/{self.session_study.id}",
            f"/edit_survey/{self.default_study.id}/{self.default_survey.id}",
            f"/interventions/{self.session_study.id}",
            # "/manage_credentials/",  # can't be in this list due to redirect safety sorta
            "/manage_firebase_credentials/",
            "/manage_researchers/",
            "/manage_studies/",  # url with both slashes
            "/manage_studies",   # url with no trailing slash
            "manage_studies/",   # url with no leading slash
            "manage_studies",    # url with no slashes
            f"/study_fields/{self.session_study.id}",
            f"/view_study/{self.session_study.id}",
            f'/view_study/{self.session_study.id}/participant/{self.default_participant.id}',
            f'/view_study/{self.session_study.id}/participant/{self.default_participant.id}/notification_history',
            f'/studies/{self.session_study.id}/forest/progress/',
            f'/studies/{self.session_study.id}/forest/tasks/',
        ]
    
    @property
    def a_valid_redirect_url(self):
        return f"/edit_study/{self.default_study.id}"
    
    def assert_url_match(self, url: str, resp: HttpResponse):
        try:
            self.assertEqual(url, resp.url)
        except AssertionError:
            self.assertEqual("/" + url, resp.url)
    
    def test_page_list_is_correct(self):
        # Now go create an explicit test for that page. These tests exist to ensure we don't have
        # code rot on this feature.
        endpoint_names = set(urlpattern.name for urlpattern in LOGIN_REDIRECT_SAFE)
        self.assertEqual(self.LOCAL_COPY_WHITELIST, endpoint_names)
        
        # Check that every endpoint is in the whitelist, starts with a slash.
        endpoint_names = set()
        for url in self.urls:
            try:
                assert url.startswith("/"), f"url '{url}' does not start with a slash"
            except AssertionError:
                # case - we have a mildly illegal url that needs to be tested along with the others
                assert url in ("manage_studies/", "manage_studies")

            found_something = False
            for urlpattern in urlpatterns:
                if urlpattern.pattern.match(url.lstrip("/")):
                    endpoint_names.add(urlpattern.name)
                    found_something = True
            assert found_something, f"no urlpattern matched url '{url}'"
        
        # test that the list of url _names_ matches the whitelist so that you get a very convenient
        # error message stating what is missing in name form! :D
        self.assertEqual(self.LOCAL_COPY_WHITELIST, endpoint_names)
    
    def test_login_page_referral_but_with_most_recent_page(self):
        self.session_researcher.update_only(most_recent_page=self.a_valid_redirect_url)
        self.test_login_page_referral()
    
    def test_login_page_referral(self):
        # self.session_researcher.update_only(most_recent_page=url)
        self.session_researcher.update_only(site_admin=True)  # make sure we have permissions...
        self.do_researcher_logout()
        
        # test that every url has the parameterized referrer url, then test that the page loads with
        # the value embedded with the referrer post parameter.
        for url in self.urls + [self.a_valid_redirect_url]:
            resp = self.client.get(url)
            # case: you actually do need the url to be valid to get a redirect To The Login page
            if url[0] != "/":
                self.assertEqual(resp.status_code, 404)
                continue
            self.assertEqual(resp.url, "/?page=/" + url.lstrip("/"))  # ensure there is a leading slash
            page = resp.client.get(resp.url).content
            self.assert_present( # ensure there is a leading slash
                f'<input type="hidden" name="referrer" value="/{url.lstrip("/")}" />', page
            )
            # test that the negative tests be based in reality
            self.assert_present('name="referrer"', page)
        
        # whn there is no change to the url we don't get a url attribute
        # test junk
        resp = self.client.get("/?page=literally junk")
        self.assertFalse(hasattr(resp, "url"))
        self.assert_not_present('name="referrer"', resp.content)
        # test blank
        resp = self.client.get("/?page=")
        self.assertFalse(hasattr(resp, "url"))
        self.assert_not_present('name="referrer"', resp.content)
        # test "/"
        resp = self.client.get("/?page=/")
        self.assertFalse(hasattr(resp, "url"))
        self.assert_not_present('name="referrer"', resp.content)
        # test a url that doesn't redirect because its not on the whitelist
        resp = self.client.get("/?page=/manage_credentials/")
        self.assertFalse(hasattr(resp, "url"))
        self.assert_not_present('name="referrer"', resp.content)
        # test a url that doesn't redirect because its on the redirects-ignore list
        resp = self.client.get("/?page=/reset_download_api_credentials/")
        self.assertFalse(hasattr(resp, "url"))
        self.assert_not_present('name="referrer"', resp.content)
        # test an injection on a valid page
        resp = self.client.get(f"/?page={self.a_valid_redirect_url}'><script>alert('hi')</script>")
        self.assertFalse(hasattr(resp, "url"))
        self.assert_not_present('name="referrer"', resp.content)
        # test html escaped version of a valid page
        resp = self.client.get(f"/?page={self.a_valid_redirect_url}".replace("_", r"%5f"))
        self.assertFalse(hasattr(resp, "url"))
        self.assert_not_present('name="referrer"', resp.content)
    
    def test_redirect_works_on_all_valid_pages_probably(self):
        self.session_researcher.update_only(site_admin=True)  # make sure we have permissions...
        
        # test that every url actually works with the redirect.
        for url in self.urls:
            self.session_researcher.update_only(most_recent_page=url)
            resp = self.do_default_login()
            self.do_researcher_logout()
            self.assert_url_match(url, resp)
    
    def test_redirect_failures(self):
        self.session_researcher.update_only(site_admin=True)  # make sure we have permissions...
        
        # test junk doesn't crash it
        self.session_researcher.update_only(most_recent_page="literally junk")
        resp = self.do_default_login()
        self.do_researcher_logout()
        self.assertEqual(resp.url, "/choose_study")
        
        # test blank
        self.session_researcher.update_only(most_recent_page="")
        resp = self.do_default_login()
        self.do_researcher_logout()
        self.assertEqual(resp.url, "/choose_study")
        
        # test None
        self.session_researcher.update_only(most_recent_page=None)
        resp = self.do_default_login()
        self.do_researcher_logout()
        self.assertEqual(resp.url, "/choose_study")
        
        # test '/' ('/' is a valid url that shouldn't redirect but is also a weird one I guess?)
        self.session_researcher.update_only(most_recent_page="/")
        resp = self.do_default_login()
        self.do_researcher_logout()
        self.assertEqual(resp.url, "/choose_study")
        
        # test for an endpoint that DOESN'T redirect because its on the redirects-ignore list
        self.session_researcher.update_only(most_recent_page="/manage_credentials/")
        resp = self.do_default_login()
        self.do_researcher_logout()
        self.assertEqual(resp.url, "/choose_study")
        
        # test a valid url that doesn't redirect because its not on the whitelist
        self.session_researcher.update_only(most_recent_page="/reset_download_api_credentials/")
        resp = self.do_default_login()
        self.do_researcher_logout()
        self.assertEqual(resp.url, "/choose_study")
    
    def test_forwarding_works_on_all_valid_pages_no_most_recent_page(self):
        self.session_researcher.update_only(site_admin=True)  # make sure we have permissions...
        self.session_researcher.update_only(most_recent_page=None)  # disable
        # test that every url actually works with the redirect.
        for url in self.urls:
            resp = self.do_default_login(referrer=url)
            self.do_researcher_logout()
            # starting slashes get inserted by the redirect logic, assert exact or missing slash matches
            self.assert_url_match(url, resp)
    
    def test_forwarding_works_on_all_valid_pages_overrides_most_recent_page(self):
        self.session_researcher.update_only(site_admin=True)  # make sure we have permissions...
        self.session_researcher.update_only(most_recent_page=self.a_valid_redirect_url)
        # test that every url actually works with the redirect.
        for url in self.urls:
            resp = self.do_default_login(referrer=url)
            self.do_researcher_logout()
            self.assert_url_match(url, resp)
    
    def test_forwarding_fails(self):
        self.session_researcher.update_only(site_admin=True)  # make sure we have permissions...
        self.session_researcher.update_only(most_recent_page=None)
        
        # test junk doesn't crash it
        resp = self.do_default_login(referrer="literally junk")
        self.do_researcher_logout()
        self.assertEqual(resp.url, "/choose_study")
        
        # test blank
        resp = self.do_default_login(referrer="")
        self.do_researcher_logout()
        self.assertEqual(resp.url, "/choose_study")
        
        # test '/' ('/' is a valid url that shouldn't redirect but is also a weird one I guess?)
        resp = self.do_default_login(referrer="/")
        self.do_researcher_logout()
        self.assertEqual(resp.url, "/choose_study")
        
        # test for an endpoint that DOESN'T redirect because its on the redirects-ignore list
        resp = self.do_default_login(referrer="/manage_credentials/")
        self.do_researcher_logout()
        self.assertEqual(resp.url, "/choose_study")
        
        # test a valid url that doesn't redirect because its not on the whitelist
        resp = self.do_default_login(referrer="/reset_download_api_credentials/")
        self.do_researcher_logout()
        self.assertEqual(resp.url, "/choose_study")
    
    def test_forwarding_fails_with_most_recent_page(self):
        self.session_researcher.update_only(site_admin=True)  # make sure we have permissions...
        redirect_page = self.a_valid_redirect_url
        self.session_researcher.update_only(most_recent_page=redirect_page)
        
        # test junk doesn't crash it
        resp = self.do_default_login(referrer="literally junk")
        self.do_researcher_logout()
        self.assertEqual(resp.url, redirect_page)
        
        # test blank
        resp = self.do_default_login(referrer="")
        self.do_researcher_logout()
        self.assertEqual(resp.url, redirect_page)
        
        # test '/' ('/' is a valid url that shouldn't redirect but is also a weird one I guess?)
        resp = self.do_default_login(referrer="/")
        self.do_researcher_logout()
        self.assertEqual(resp.url, redirect_page)
        
        # test for an endpoint that DOESN'T redirect because its on the redirects-ignore list
        resp = self.do_default_login(referrer="/manage_credentials/")
        self.do_researcher_logout()
        self.assertEqual(resp.url, redirect_page)
        
        # test a valid url that doesn't redirect because its not on the whitelist
        resp = self.do_default_login(referrer="/reset_download_api_credentials/")
        self.do_researcher_logout()
        self.assertEqual(resp.url, redirect_page)
#
## admin_pages
#

class TestViewStudy(ResearcherSessionTest):
    """ view_study is pretty simple, no custom content in the :
    tests push_notifications_enabled, study.is_test, study.forest_enabled
    populates html elements with custom field values
    populates html elements of survey buttons """
    
    ENDPOINT_NAME = "admin_pages.view_study"
    
    def test_view_study_no_relation(self):
        self.smart_get_status_code(403, self.session_study.id)
    
    def test_view_study_researcher(self):
        study = self.session_study
        study.update(is_test=True)
        self.set_session_study_relation(ResearcherRole.researcher)
        response = self.smart_get_status_code(200, study.id)
        
        # template has several customizations, test for some relevant strings
        self.assertNotIn(b"data in this study is restricted", response.content)
        study.update(is_test=False)
        
        response = self.smart_get_status_code(200, study.id)
        self.assertIn(b"data in this study is restricted", response.content)
    
    def test_view_study_study_admin(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self.smart_get_status_code(200, self.session_study.id)
    
    @patch('pages.admin_pages.check_firebase_instance')
    def test_view_study_site_admin(self, check_firebase_instance: MagicMock):
        study = self.session_study
        self.set_session_study_relation(ResearcherRole.site_admin)
        
        # test rendering with several specifc values set to observe the rendering changes
        study.update(forest_enabled=False)
        check_firebase_instance.return_value = False
        response = self.smart_get_status_code(200, study.id)
        self.assertNotIn(b"Configure Interventions for use with Relative survey schedules", response.content)
        self.assertNotIn(b"View Forest Task Log", response.content)
        
        check_firebase_instance.return_value = True
        study.update(forest_enabled=True)
        response = self.smart_get_status_code(200, study.id)
        self.assertIn(b"Configure Interventions for use with Relative survey schedules", response.content)
        self.assertIn(b"View Forest Task Log", response.content)
        # assertInHTML is several hundred times slower but has much better output when it fails...
        # self.assertInHTML("Configure Interventions for use with Relative survey schedules", response.content.decode())


class TestManageCredentials(ResearcherSessionTest):
    ENDPOINT_NAME = "admin_pages.manage_credentials"
    
    def test_manage_credentials(self):
        self.session_study
        self.smart_get_status_code(200)
        api_key = ApiKey.generate(
            researcher=self.session_researcher,
            has_tableau_api_permissions=True,
            readable_name="not important",
        )
        response = self.smart_get_status_code(200)
        self.assert_present(api_key.access_key_id, response.content)
    
    def test_mfa_not_visible(self):
        # qr code should only be visible if mfa password was provided (and matches) and session does
        # not contain the MFA_CREATED key
        session = self.client.session  # this creates a new object
        self.session_researcher.reset_mfa()
        # use the alt text to test for presence of the qr code
        self.assert_not_present('alt="MFA QR Code"', self.smart_get_status_code(200).content)
        session[MFA_CREATED] = timezone.now() - timedelta(seconds=60)
        session.save()
        self.assert_not_present('alt="MFA QR Code"', self.smart_get_status_code(200).content)
    
    def test_mfa_visible_session_manip(self):
        session = self.client.session  # this creates a new object
        self.session_researcher.reset_mfa()
        session[MFA_CREATED] = timezone.now()
        session.save()  # save the session because this isn't inside the request/response cycle
        self.assert_present('alt="MFA QR Code"', self.smart_get_status_code(200).content)
    
    def test_mfa_visible_password(self):
        self.session_researcher.reset_mfa()
        resp = self.smart_post_status_code(200, view_mfa_password=self.DEFAULT_RESEARCHER_PASSWORD)
        self.assert_present('alt="MFA QR Code"', resp.content)


class TestResetAdminPassword(ResearcherSessionTest):
    # test for every case and messages present on the page
    ENDPOINT_NAME = "admin_pages.reset_admin_password"
    REDIRECT_ENDPOINT_NAME = "admin_pages.manage_credentials"
    
    def test_reset_admin_password_success(self):
        resp = self.smart_post_status_code(
            302,
            current_password=self.DEFAULT_RESEARCHER_PASSWORD,
            new_password=self.DEFAULT_RESEARCHER_PASSWORD + "1",
            confirm_new_password=self.DEFAULT_RESEARCHER_PASSWORD + "1",
        )
        # the initial redirect is to the normal endpoint
        self.assertEqual(resp.url, easy_url(self.REDIRECT_ENDPOINT_NAME))
        
        r = self.session_researcher
        r.refresh_from_db()
        self.assertFalse(r.check_password(r.username, self.DEFAULT_RESEARCHER_PASSWORD))
        self.assertTrue(r.check_password(r.username, self.DEFAULT_RESEARCHER_PASSWORD + "1"))
        r.force_global_logout()
        self.assertEqual(self.session_researcher.web_sessions.count(), 0)
        resp = self.easy_get(self.REDIRECT_ENDPOINT_NAME, 302)
        self.assertEqual(resp.url, easy_url("login_pages.login_page"))
        resp = self.easy_get("login_pages.login_page", 200)
        self.assert_present(PASSWORD_RESET_SUCCESS, resp.content)
    
    def test_reset_admin_password_wrong(self):
        self.smart_post(
            current_password=self.DEFAULT_RESEARCHER_PASSWORD + "1",
            new_password=self.DEFAULT_RESEARCHER_PASSWORD + "1",
            confirm_new_password=self.DEFAULT_RESEARCHER_PASSWORD + "1",
        )
        r = self.session_researcher
        self.assertTrue(r.check_password(r.username, self.DEFAULT_RESEARCHER_PASSWORD))
        self.assertFalse(r.check_password(r.username, self.DEFAULT_RESEARCHER_PASSWORD + "1"))
        self.assert_present(WRONG_CURRENT_PASSWORD, self.redirect_get_contents())
    
    def test_reset_admin_password_rules_fail(self):
        non_default = "abcdefghijklmnop"
        self.smart_post(
            current_password=self.DEFAULT_RESEARCHER_PASSWORD,
            new_password=non_default,
            confirm_new_password=non_default,
        )
        r = self.session_researcher
        self.assertTrue(r.check_password(r.username, self.DEFAULT_RESEARCHER_PASSWORD))
        self.assertFalse(r.check_password(r.username, non_default))
        self.assert_present(NEW_PASSWORD_RULES_FAIL, self.redirect_get_contents())
    
    def test_reset_admin_password_too_short(self):
        non_default = "a1#"
        self.smart_post(
            current_password=self.DEFAULT_RESEARCHER_PASSWORD,
            new_password=non_default,
            confirm_new_password=non_default,
        )
        r = self.session_researcher
        self.assertTrue(r.check_password(r.username, self.DEFAULT_RESEARCHER_PASSWORD))
        self.assertFalse(r.check_password(r.username, non_default))
        self.assert_present(NEW_PASSWORD_N_LONG.format(length=8), self.redirect_get_contents())
    
    def test_reset_admin_password_too_short_study_setting(self):
        self.session_study.update(password_minimum_length=20)
        self.set_session_study_relation(ResearcherRole.researcher)
        non_default = "aA1#aA1#aA1#aA1#"  # 10 chars
        self.smart_post(
            current_password=self.DEFAULT_RESEARCHER_PASSWORD,
            new_password=non_default,
            confirm_new_password=non_default,
        )
        r = self.session_researcher
        self.assertTrue(r.check_password(r.username, self.DEFAULT_RESEARCHER_PASSWORD))
        self.assertFalse(r.check_password(r.username, non_default))
        self.assert_present(NEW_PASSWORD_N_LONG.format(length=20), self.redirect_get_contents())
    
    def test_reset_admin_password_too_short_site_admin(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        non_default = "aA1#aA1#aA1#aA1#"  # 10 chars
        self.smart_post(
            current_password=self.DEFAULT_RESEARCHER_PASSWORD,
            new_password=non_default,
            confirm_new_password=non_default,
        )
        r = self.session_researcher
        self.assertTrue(r.check_password(r.username, self.DEFAULT_RESEARCHER_PASSWORD))
        self.assertFalse(r.check_password(r.username, non_default))
        self.assert_present(NEW_PASSWORD_N_LONG.format(length=20), self.redirect_get_contents())
    
    def test_reset_admin_password_mismatch(self):
        # has to pass the length and character checks
        self.smart_post(
            current_password=self.DEFAULT_RESEARCHER_PASSWORD,
            new_password="aA1#aA1#aA1#",
            confirm_new_password="aA1#aA1#aA1#aA1#",
        )
        researcher = self.session_researcher
        self.assertTrue(researcher.check_password(researcher.username, self.DEFAULT_RESEARCHER_PASSWORD))
        self.assertFalse(researcher.check_password(researcher.username, "aA1#aA1#aA1#"))
        self.assertFalse(researcher.check_password(researcher.username, "aA1#aA1#aA1#aA1#"))
        self.assert_present(NEW_PASSWORD_MISMATCH, self.redirect_get_contents())


class TestResetDownloadApiCredentials(ResearcherSessionTest):
    ENDPOINT_NAME = "admin_pages.reset_download_api_credentials"
    REDIRECT_ENDPOINT_NAME = "admin_pages.manage_credentials"
    
    def test_reset(self):
        self.assertIsNone(self.session_researcher.access_key_id)
        self.smart_post()
        self.session_researcher.refresh_from_db()
        self.assertIsNotNone(self.session_researcher.access_key_id)
        self.assert_present("Your Data-Download API access credentials have been reset",
                             self.redirect_get_contents())


class TestNewTableauApiKey(ResearcherSessionTest):
    ENDPOINT_NAME = "admin_pages.new_tableau_api_key"
    REDIRECT_ENDPOINT_NAME = "admin_pages.manage_credentials"
    
    # FIXME: add tests for sanitization of the input name
    def test_reset(self):
        self.assertIsNone(self.session_researcher.api_keys.first())
        self.smart_post(readable_name="new_name")
        self.assertIsNotNone(self.session_researcher.api_keys.first())
        self.assert_present("New Tableau API credentials have been generated for you",
                             self.redirect_get_contents())
        self.assertEqual(ApiKey.objects.filter(
            researcher=self.session_researcher, readable_name="new_name").count(), 1)


# admin_pages.disable_tableau_api_key
class TestDisableTableauApiKey(ResearcherSessionTest):
    ENDPOINT_NAME = "admin_pages.disable_tableau_api_key"
    REDIRECT_ENDPOINT_NAME = "admin_pages.manage_credentials"
    
    def test_disable_success(self):
        # basic test
        api_key = ApiKey.generate(
            researcher=self.session_researcher,
            has_tableau_api_permissions=True,
            readable_name="something",
        )
        self.smart_post(api_key_id=api_key.access_key_id)
        self.assertFalse(self.session_researcher.api_keys.first().is_active)
        content = self.redirect_get_contents()
        self.assert_present(api_key.access_key_id, content)
        self.assert_present("is now disabled", content)
    
    def test_no_match(self):
        # fail with empty and fail with success
        self.smart_post(api_key_id="abc")
        self.assert_present(TABLEAU_NO_MATCHING_API_KEY, self.redirect_get_contents())
        api_key = ApiKey.generate(
            researcher=self.session_researcher,
            has_tableau_api_permissions=True,
            readable_name="something",
        )
        self.smart_post(api_key_id="abc")
        api_key.refresh_from_db()
        self.assertTrue(api_key.is_active)
        self.assert_present(TABLEAU_NO_MATCHING_API_KEY, self.redirect_get_contents())
    
    def test_already_disabled(self):
        api_key = ApiKey.generate(
            researcher=self.session_researcher,
            has_tableau_api_permissions=True,
            readable_name="something",
        )
        api_key.update(is_active=False)
        self.smart_post(api_key_id=api_key.access_key_id)
        api_key.refresh_from_db()
        self.assertFalse(api_key.is_active)
        self.assert_present(TABLEAU_API_KEY_IS_DISABLED, self.redirect_get_contents())


#
## dashboard_api
#

class TestDashboard(ResearcherSessionTest):
    ENDPOINT_NAME = "dashboard_api.dashboard_page"
    
    def assert_data_streams_present(self, resp: HttpResponse):
        for data_stream_text in COMPLETE_DATA_STREAM_DICT.values():
            self.assert_present(data_stream_text, resp.content)
    
    def test_dashboard_no_participants(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        resp = self.smart_get_status_code(200, str(self.session_study.id))
        self.assert_present("Choose a participant or data stream to view", resp.content)
        self.assert_not_present(self.DEFAULT_PARTICIPANT_NAME, resp.content)
        self.assert_data_streams_present(resp)
    
    def test_dashboard_one_participant(self):
        self.default_participant
        # default user and default study already instantiated
        self.set_session_study_relation(ResearcherRole.researcher)
        resp = self.smart_get_status_code(200, str(self.session_study.id))
        self.assert_present("Choose a participant or data stream to view", resp.content)
        self.assert_present(self.DEFAULT_PARTICIPANT_NAME, resp.content)
        self.assert_data_streams_present(resp)
    
    def test_dashboard_many_participant(self):
        particpiants = self.generate_10_default_participants
        # default user and default study already instantiated
        self.set_session_study_relation(ResearcherRole.researcher)
        resp = self.smart_get_status_code(200, str(self.session_study.id))
        self.assert_present("Choose a participant or data stream to view", resp.content)
        for p in particpiants:
            self.assert_present(p.patient_id, resp.content)
        self.assert_data_streams_present(resp)


# FIXME: dashboard is going to require a fixture to populate data.
class TestDashboardStream(ResearcherSessionTest):
    ENDPOINT_NAME = "dashboard_api.get_data_for_dashboard_datastream_display"
    
    def test_no_participant(self):
        self.do_data_stream_test(create_chunkregistries=False, number_participants=0)
    
    def test_one_participant_no_data(self):
        self.do_data_stream_test(create_chunkregistries=False, number_participants=1)
    
    def test_three_participants_no_data(self):
        self.do_data_stream_test(create_chunkregistries=False, number_participants=3)
    
    def test_five_participants_with_data(self):
        self.do_data_stream_test(create_chunkregistries=True, number_participants=5)
    
    def do_data_stream_test(self, create_chunkregistries=False, number_participants=1):
        # self.default_participant  < -- breaks, collision with default name.
        self.set_session_study_relation()
        participants: List[Participant] = [
            self.generate_participant(self.session_study, patient_id=f"patient{i+1}")
            for i in range(number_participants)
        ]
        
        # create all the participants we need
        if create_chunkregistries:
            for i, participant in enumerate(participants, start=0):
                self.generate_chunkregistry(
                    self.session_study,
                    participant,
                    "junk",  # data_stream
                    file_size=123456+i,
                    time_bin=timezone.localtime().replace(hour=i, minute=0, second=0, microsecond=0),
                )
        
        for data_stream in DASHBOARD_DATA_STREAMS:
            if create_chunkregistries:  # force correct data type
                ChunkRegistry.objects.all().update(data_type=data_stream)
            
            html1 = self.smart_get_status_code(200, self.session_study.id, data_stream).content
            html2 = self.smart_post_status_code(200, self.session_study.id, data_stream).content
            title = COMPLETE_DATA_STREAM_DICT[data_stream]
            self.assert_present(title, html1)
            self.assert_present(title, html2)
            
            for i, participant in enumerate(participants, start=0):
                comma_separated = str(123456 + i)[:-3] + "," + str(123456 + i)[3:]
                if create_chunkregistries:
                    self.assert_present(participant.patient_id, html1)
                    self.assert_present(participant.patient_id, html2)
                    self.assert_present(comma_separated, html1)
                    self.assert_present(comma_separated, html2)
                else:
                    self.assert_not_present(participant.patient_id, html1)
                    self.assert_not_present(participant.patient_id, html2)
                    self.assert_not_present(comma_separated, html1)
                    self.assert_not_present(comma_separated, html2)
            
            if not participants or not create_chunkregistries:
                self.assert_present(f"There is no data currently available for {title}", html1)
                self.assert_present(f"There is no data currently available for {title}", html2)


# FIXME: this page renders with almost no data
class TestDashboardPatientDisplay(ResearcherSessionTest):
    ENDPOINT_NAME = "dashboard_api.dashboard_participant_page"
    
    def test_patient_display_no_data(self):
        self.set_session_study_relation()
        resp = self.smart_get_status_code(200, self.session_study.id, self.default_participant.patient_id)
        self.assert_present("There is no data currently available for patient1 of Study", resp.content)
    
    def test_five_participants_with_data(self):
        self.set_session_study_relation()
        
        for i in range(10):
            self.generate_chunkregistry(
                self.session_study,
                self.default_participant,
                ACCELEROMETER,  # data_stream
                file_size=123456,
                time_bin=timezone.localtime().replace(hour=i, minute=0, second=0, microsecond=0),
            )
        
        # need to be post and get requests, it was just built that way
        html1 = self.smart_get_status_code(
            200, self.session_study.id, self.default_participant.patient_id).content
        html2 = self.smart_post_status_code(
            200, self.session_study.id, self.default_participant.patient_id).content
        title = COMPLETE_DATA_STREAM_DICT[ACCELEROMETER]
        self.assert_present(title, html1)
        self.assert_present(title, html2)
        # test for value of 10x for 1 day of 10 hours of data
        comma_separated = "1,234,560"
        for title in COMPLETE_DATA_STREAM_DICT.values():
            self.assert_present(title, html1)
            self.assert_present(title, html2)
        
        self.assert_present(self.default_participant.patient_id, html1)
        self.assert_present(self.default_participant.patient_id, html2)
        self.assert_present(comma_separated, html1)
        self.assert_present(comma_separated, html2)


#
## system_admin_pages
#

class TestManageResearchers(ResearcherSessionTest):
    ENDPOINT_NAME = "system_admin_pages.manage_researchers"
    
    def test_researcher(self):
        self.smart_get_status_code(403)
    
    def test_study_admin(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self.smart_get_status_code(200)
    
    def test_site_admin(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        self.smart_get_status_code(200)
    
    def test_render_study_admin(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self._test_render_with_researchers()
        # make sure that site admins are not present
        r4 = self.generate_researcher(relation_to_session_study=ResearcherRole.site_admin)
        resp = self.smart_get_status_code(200)
        self.assert_not_present(r4.username, resp.content)
        
        # make sure that unaffiliated researchers are not present
        r5 = self.generate_researcher()
        resp = self.smart_get_status_code(200)
        self.assert_not_present(r5.username, resp.content)
    
    def test_render_site_admin(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        self._test_render_with_researchers()
        # make sure that site admins ARE present
        r4 = self.generate_researcher(relation_to_session_study=ResearcherRole.site_admin)
        resp = self.smart_get_status_code(200)
        self.assert_present(r4.username, resp.content)
        
        # make sure that unaffiliated researchers ARE present
        r5 = self.generate_researcher()
        resp = self.smart_get_status_code(200)
        self.assert_present(r5.username, resp.content)
    
    def _test_render_with_researchers(self):
        # render the page with a regular user
        r2 = self.generate_researcher(relation_to_session_study=ResearcherRole.researcher)
        resp = self.smart_get_status_code(200)
        self.assert_present(r2.username, resp.content)
        
        # render with 2 reseaorchers
        r3 = self.generate_researcher(relation_to_session_study=ResearcherRole.researcher)
        resp = self.smart_get_status_code(200)
        self.assert_present(r2.username, resp.content)
        self.assert_present(r3.username, resp.content)


class TestResetResearcherMFA(ResearcherSessionTest):
    ENDPOINT_NAME = "system_admin_pages.reset_researcher_mfa"
    REDIRECT_ENDPOINT_NAME = "system_admin_pages.edit_researcher"
    
    def test_reset_as_site_admin(self):
        self._test_reset(self.generate_researcher(), ResearcherRole.site_admin)
    
    def test_reset_as_site_admin_on_site_admin(self):
        researcher = self.generate_researcher()
        self.generate_study_relation(researcher, self.session_study, ResearcherRole.site_admin)
        self._test_reset(researcher, ResearcherRole.site_admin)
    
    def test_reset_as_study_admin_on_good_researcher(self):
        researcher = self.generate_researcher()
        self.generate_study_relation(researcher, self.session_study, ResearcherRole.researcher)
        self._test_reset(researcher, ResearcherRole.study_admin)
    
    def test_reset_as_study_admin_on_bad_researcher(self):
        researcher = self.generate_researcher()
        self._test_reset_fail(researcher, ResearcherRole.study_admin, 403)
    
    def test_reset_as_study_admin_on_site_admin(self):
        researcher = self.generate_researcher()
        self.generate_study_relation(researcher, self.session_study, ResearcherRole.site_admin)
        self._test_reset_fail(researcher, ResearcherRole.study_admin, 403)
    
    def test_reset_study_admin_with_good_study_admin(self):
        researcher = self.generate_researcher()
        self.generate_study_relation(researcher, self.session_study, ResearcherRole.study_admin)
        self._test_reset(researcher, ResearcherRole.study_admin)
    
    def test_no_researcher(self):
        # basically, it should 404
        self.set_session_study_relation(ResearcherRole.site_admin)
        resp = self.smart_post(0)  # not the magic redirect smart post; 0 will always be an invalid researcher id
        self.assertEqual(404, resp.status_code)
    
    def _test_reset(self, researcher: Researcher, role: ResearcherRole):
        researcher.reset_mfa()
        self.set_session_study_relation(role)
        self.smart_post(researcher.id)  # magic redirect smart post, tests for a redirect
        researcher.refresh_from_db()
        self.assertIsNone(researcher.mfa_token)
        resp = self.easy_get(self.REDIRECT_ENDPOINT_NAME, researcher_pk=researcher.id)
        self.assert_present("MFA token cleared for researcher ", resp.content)
    
    def _test_reset_fail(self, researcher: Researcher, role: ResearcherRole, status_code: int):
        researcher.reset_mfa()
        self.set_session_study_relation(role)
        resp = self.smart_post(researcher.id)  # not the magic redirect smart post; 0 will always be an invalid researcher id
        self.assertEqual(status_code, resp.status_code)
        researcher.refresh_from_db()
        self.assertIsNotNone(researcher.mfa_token)
        resp = self.easy_get(self.REDIRECT_ENDPOINT_NAME, researcher_pk=researcher.id)
        if resp.status_code == 403:
            self.assert_present(MFA_RESET_BAD_PERMISSIONS, resp.content)


class TestEditResearcher(ResearcherSessionTest):
    ENDPOINT_NAME = "system_admin_pages.edit_researcher"
    
    # render self
    def test_render_for_self_as_researcher(self):
        # should fail
        self.set_session_study_relation()
        self.smart_get_status_code(403, self.session_researcher.id)
    
    def test_render_for_self_as_study_admin(self):
        # ensure it renders (buttons will be disabled)
        self.set_session_study_relation(ResearcherRole.study_admin)
        self.smart_get_status_code(200, self.session_researcher.id)
    
    def test_render_for_self_as_site_admin(self):
        # ensure it renders (buttons will be disabled)
        self.set_session_study_relation(ResearcherRole.site_admin)
        self.smart_get_status_code(200, self.session_researcher.id)
    
    def test_render_for_researcher_as_researcher(self):
        # should fail
        self.set_session_study_relation()
        # set up, test when not on study
        r2 = self.generate_researcher()
        resp = self.smart_get_status_code(403, r2.id)
        self.assert_not_present(r2.username, resp.content)
        # attach other researcher and try again
        self.generate_study_relation(r2, self.session_study, ResearcherRole.researcher)
        resp = self.smart_get_status_code(403, r2.id)
        self.assert_not_present(r2.username, resp.content)
    
    # study admin, renders
    def test_render_valid_researcher_as_study_admin(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self._test_render_generic_under_study()
    
    def test_render_researcher_with_no_study_as_study_admin(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self._test_render_researcher_with_no_study()
    
    # site admin, renders
    def test_render_valid_researcher_as_site_admin(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        self._test_render_generic_under_study()
    
    def test_render_researcher_with_no_study_as_site_admin(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        self._test_render_researcher_with_no_study()
    
    def _test_render_generic_under_study(self):
        r2 = self.generate_researcher(relation_to_session_study=ResearcherRole.researcher)
        resp = self.smart_get_status_code(200, r2.id)
        self.assert_present(r2.username, resp.content)
    
    def _test_render_researcher_with_no_study(self):
        r2 = self.generate_researcher()
        resp = self.smart_get_status_code(200, r2.id)
        self.assert_present(r2.username, resp.content)


#
## admin_pages
#

class TestResetMFASelf(ResearcherSessionTest):
    ENDPOINT_NAME = "admin_pages.reset_mfa_self"
    REDIRECT_ENDPOINT_NAME = "admin_pages.manage_credentials"
    
    def test_no_password(self):
        session = self.client.session
        orig_mfa = self.session_researcher.reset_mfa()
        self.smart_post()  # magic redirect smart post, tests for the redirect
        resp = self.easy_get(self.REDIRECT_ENDPOINT_NAME)
        self.assert_present(MFA_SELF_NO_PASSWORD, resp.content)
        self.session_researcher.refresh_from_db()
        self.assertIsNotNone(self.session_researcher.mfa_token)
        self.assertEqual(orig_mfa, self.session_researcher.mfa_token)  # no change
        self.assertNotIn(MFA_CREATED, session)
    
    def test_bad_password(self):
        session = self.client.session
        orig_mfa = self.session_researcher.reset_mfa()
        self.smart_post(mfa_password="wrong_password")  # magic redirect smart post
        resp = self.easy_get(self.REDIRECT_ENDPOINT_NAME)
        self.assert_present(MFA_SELF_BAD_PASSWORD, resp.content)
        self.assertIsNotNone(self.session_researcher.mfa_token)
        self.assertEqual(orig_mfa, self.session_researcher.mfa_token)  # no change
        self.assertNotIn(MFA_CREATED, session)
    
    def test_mfa_reset_with_mfa_token(self):
        # case is not accessible from webpage
        session = self.client.session
        orig_mfa = self.session_researcher.reset_mfa()
        self.smart_post(mfa_password=self.DEFAULT_RESEARCHER_PASSWORD)  # magic redirect smart post
        resp = self.easy_get(self.REDIRECT_ENDPOINT_NAME)
        self.assert_present(MFA_SELF_SUCCESS, resp.content)
        self.session_researcher.refresh_from_db()
        self.assertIsNotNone(self.session_researcher.mfa_token)
        self.assertNotEqual(orig_mfa, self.session_researcher.mfa_token)  # change!
        self.assertIn(MFA_CREATED, session)
    
    def test_mfa_reset_without_mfa_token(self):
        session = self.client.session
        self.smart_post(mfa_password=self.DEFAULT_RESEARCHER_PASSWORD)  # magic redirect smart post
        resp = self.easy_get(self.REDIRECT_ENDPOINT_NAME)
        self.assert_present(MFA_SELF_SUCCESS, resp.content)
        self.session_researcher.refresh_from_db()
        self.assertIsNotNone(self.session_researcher.mfa_token)  # change!
        self.assertIn(MFA_CREATED, session)
    
    def test_mfa_clear_with_token(self):
        session = self.client.session
        orig_mfa = self.session_researcher.reset_mfa()
        # disable can be any non-falsy value
        self.smart_post(mfa_password=self.DEFAULT_RESEARCHER_PASSWORD, disable="true")
        resp = self.easy_get(self.REDIRECT_ENDPOINT_NAME)
        self.assert_present(MFA_SELF_DISABLED, resp.content)
        self.session_researcher.refresh_from_db()
        self.assertIsNone(self.session_researcher.mfa_token)
        self.assertNotEqual(orig_mfa, self.session_researcher.mfa_token)  # change!
        self.assertNotIn(MFA_CREATED, session)
    
    def test_mfa_clear_without_mfa_token(self):
        session = self.client.session
        # disable can be any non-falsy value
        self.smart_post(mfa_password=self.DEFAULT_RESEARCHER_PASSWORD, disable="true")
        resp = self.easy_get(self.REDIRECT_ENDPOINT_NAME)
        self.assert_present(MFA_SELF_DISABLED, resp.content)
        self.session_researcher.refresh_from_db()
        self.assertIsNone(self.session_researcher.mfa_token)  # change!
        self.assertNotIn(MFA_CREATED, session)


class TestTestMFA(ResearcherSessionTest):
    ENDPOINT_NAME = "admin_pages.test_mfa"
    REDIRECT_ENDPOINT_NAME = "admin_pages.manage_credentials"
    
    def test_mfa_working_fails(self):
        self.session_researcher.reset_mfa()  # enable mfa
        if self.session_researcher._mfa_now == "123456":
            self.session_researcher.reset_mfa()  # ensure mfa code is not 123456
        
        self.smart_post()  # magic redirect smart post
        page = self.simple_get(easy_url("admin_pages.manage_credentials"), status_code=200).content
        self.assert_present(MFA_CODE_MISSING, page)  # missing mfa code
        
        self.smart_post(mfa_code="123456")  # wrong mfa code
        page = self.simple_get(easy_url("admin_pages.manage_credentials"), status_code=200).content
        self.assert_present(MFA_TEST_FAIL, page)
        
        self.smart_post(mfa_code="1234567")  # too long mfa code
        page = self.simple_get(easy_url("admin_pages.manage_credentials"), status_code=200).content
        self.assert_present(MFA_CODE_6_DIGITS, page)
        
        self.smart_post(mfa_code="abcdef")  # non-numeric mfa code
        page = self.simple_get(easy_url("admin_pages.manage_credentials"), status_code=200).content
        self.assert_present(MFA_CODE_DIGITS_ONLY, page)
        
        self.smart_post(mfa_code=self.session_researcher._mfa_now)  # correct mfa code
        page = self.simple_get(easy_url("admin_pages.manage_credentials"), status_code=200).content
        self.assert_present(MFA_TEST_SUCCESS, page)
        
        self.session_researcher.clear_mfa()  # disabled mfa
        self.smart_post(mfa_code="abcdef")
        page = self.simple_get(easy_url("admin_pages.manage_credentials"), status_code=200).content
        self.assert_present(MFA_TEST_DISABLED, page)


class TestElevateResearcher(ResearcherSessionTest):
    ENDPOINT_NAME = "system_admin_pages.elevate_researcher"
    # (this one is tedious.)
    
    def test_self_as_researcher_on_study(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        self.smart_post_status_code(
            403, researcher_id=self.session_researcher.id, study_id=self.session_study.id
        )
    
    def test_self_as_study_admin_on_study(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self.smart_post_status_code(
            403, researcher_id=self.session_researcher.id, study_id=self.session_study.id
        )
    
    def test_researcher_as_study_admin_on_study(self):
        # this is the only case that succeeds
        self.set_session_study_relation(ResearcherRole.study_admin)
        r2 = self.generate_researcher(relation_to_session_study=ResearcherRole.researcher)
        self.smart_post_status_code(302, researcher_id=r2.id, study_id=self.session_study.id)
        self.assertEqual(r2.study_relations.get().relationship, ResearcherRole.study_admin)
    
    def test_study_admin_as_study_admin_on_study(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        r2 = self.generate_researcher(relation_to_session_study=ResearcherRole.study_admin)
        self.smart_post_status_code(403, researcher_id=r2.id, study_id=self.session_study.id)
        self.assertEqual(r2.study_relations.get().relationship, ResearcherRole.study_admin)
    
    def test_site_admin_as_study_admin_on_study(self):
        self.session_researcher
        self.set_session_study_relation(ResearcherRole.study_admin)
        r2 = self.generate_researcher(relation_to_session_study=ResearcherRole.site_admin)
        self.smart_post_status_code(403, researcher_id=r2.id, study_id=self.session_study.id)
        self.assertFalse(r2.study_relations.filter(study=self.session_study).exists())
    
    def test_site_admin_as_site_admin(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        r2 = self.generate_researcher(relation_to_session_study=ResearcherRole.site_admin)
        self.smart_post_status_code(403, researcher_id=r2.id, study_id=self.session_study.id)
        self.assertFalse(r2.study_relations.filter(study=self.session_study).exists())


class TestDemoteStudyAdmin(ResearcherSessionTest):
    # FIXME: this endpoint does not test for site admin cases correctly, the test passes but is
    # wrong. Behavior is fine because it has no relevant side effects except for the know bug where
    # site admins need to be manually added to a study before being able to download data.
    ENDPOINT_NAME = "system_admin_pages.demote_study_admin"
    
    def test_researcher_as_researcher(self):
        r2 = self.generate_researcher(relation_to_session_study=ResearcherRole.researcher)
        self.smart_post_status_code(403, researcher_id=r2.id, study_id=self.session_study.id)
        self.assertEqual(r2.study_relations.get().relationship, ResearcherRole.researcher)
    
    def test_researcher_as_study_admin(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        r2 = self.generate_researcher(relation_to_session_study=ResearcherRole.researcher)
        self.smart_post_status_code(302, researcher_id=r2.id, study_id=self.session_study.id)
        self.assertEqual(r2.study_relations.get().relationship, ResearcherRole.researcher)
    
    def test_study_admin_as_admin(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        r2 = self.generate_researcher(relation_to_session_study=ResearcherRole.study_admin)
        self.smart_post_status_code(302, researcher_id=r2.id, study_id=self.session_study.id)
        self.assertEqual(r2.study_relations.get().relationship, ResearcherRole.researcher)
    
    def test_site_admin_as_study_admin(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        r2 = self.generate_researcher(relation_to_session_study=ResearcherRole.site_admin)
        self.smart_post_status_code(302, researcher_id=r2.id, study_id=self.session_study.id)
        self.assertFalse(r2.study_relations.exists())
        r2.refresh_from_db()
        self.assertTrue(r2.site_admin)
    
    def test_site_admin_as_site_admin(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        r2 = self.generate_researcher(relation_to_session_study=ResearcherRole.site_admin)
        self.smart_post_status_code(302, researcher_id=r2.id, study_id=self.session_study.id)
        self.assertFalse(r2.study_relations.exists())
        r2.refresh_from_db()
        self.assertTrue(r2.site_admin)


class TestCreateNewResearcher(ResearcherSessionTest):
    """ Admins should be able to create and load the page. """
    ENDPOINT_NAME = "system_admin_pages.create_new_researcher"
    
    def test_load_page_at_endpoint(self):
        # This test should be transformed into a separate endpoint
        for user_role in ALL_RESEARCHER_TYPES:
            prior_researcher_count = Researcher.objects.count()
            self.assign_role(self.session_researcher, user_role)
            resp = self.smart_get()
            if user_role in ADMIN_ROLES:
                self.assertEqual(resp.status_code, 200)
            else:
                self.assertEqual(resp.status_code, 403)
            self.assertEqual(prior_researcher_count, Researcher.objects.count())
    
    def test_create_researcher(self):
        for user_role in ALL_RESEARCHER_TYPES:
            prior_researcher_count = Researcher.objects.count()
            self.assign_role(self.session_researcher, user_role)
            username = generate_easy_alphanumeric_string()
            password = generate_easy_alphanumeric_string()
            resp = self.smart_post(admin_id=username, password=password)
            
            if user_role in ADMIN_ROLES:
                self.assertEqual(resp.status_code, 302)
                self.assertEqual(prior_researcher_count + 1, Researcher.objects.count())
                self.assertTrue(Researcher.check_password(username, password))
            else:
                self.assertEqual(resp.status_code, 403)
                self.assertEqual(prior_researcher_count, Researcher.objects.count())


class TestManageStudies(ResearcherSessionTest):
    """ All we do with this page is make sure it loads... there isn't much to hook onto and
    determine a failure or a success... the study names are always present in the json on the
    html... """
    ENDPOINT_NAME = "system_admin_pages.manage_studies"
    
    def test(self):
        for user_role in ALL_TESTING_ROLES:
            self.assign_role(self.session_researcher, user_role)
            resp = self.smart_get()
            if user_role in ADMIN_ROLES:
                self.assertEqual(resp.status_code, 200)
            else:
                self.assertEqual(resp.status_code, 403)


class TestEditStudy(ResearcherSessionTest):
    """ Test basics of permissions, test details of the study are appropriately present on page... """
    ENDPOINT_NAME = "system_admin_pages.edit_study"
    
    def test_only_admins_allowed(self):
        for user_role in ALL_TESTING_ROLES:
            self.assign_role(self.session_researcher, user_role)
            self.smart_get_status_code(
                200 if user_role in ADMIN_ROLES else 403,
                self.session_study.id
            )
    
    def test_content_study_admin(self):
        """ tests that various important pieces of information are present """
        self.set_session_study_relation(ResearcherRole.study_admin)
        self.session_study.update(is_test=True, forest_enabled=False)
        resp1 = self.smart_get_status_code(200, self.session_study.id)
        self.assert_present("Enable Forest", resp1.content)
        self.assert_not_present("Disable Forest", resp1.content)
        self.assert_present(self.session_researcher.username, resp1.content)
        
        self.session_study.update(is_test=False, forest_enabled=True)
        r2 = self.generate_researcher(relation_to_session_study=ResearcherRole.researcher)
        
        resp2 = self.smart_get_status_code(200, self.session_study.id)
        self.assert_present(self.session_researcher.username, resp2.content)
        self.assert_present(r2.username, resp2.content)
        self.assert_present("data in this study is restricted", resp2.content)


# FIXME: need to implement tests for copy study.
# FIXME: this test is not well factored, it doesn't follow a common pattern.
class TestCreateStudy(ResearcherSessionTest):
    ENDPOINT_NAME = "system_admin_pages.create_study"
    NEW_STUDY_NAME = "something anything"
    
    @property
    def get_the_new_study(self):
        return Study.objects.get(name=self.NEW_STUDY_NAME)
    
    @property
    def assert_no_new_study(self):
        self.assertFalse(Study.objects.filter(name=self.NEW_STUDY_NAME).exists())
    
    def create_study_params(self):
        """ keys are: name, encryption_key, is_test, copy_existing_study, forest_enabled """
        params = dict(
            name=self.NEW_STUDY_NAME,
            encryption_key="a" * 32,
            is_test="true",
            copy_existing_study="",
            forest_enabled="false",
        )
        return params
    
    def test_load_page(self):
        # only site admins can load the page
        for user_role in ALL_TESTING_ROLES:
            self.assign_role(self.session_researcher, user_role)
            self.smart_get_status_code(200 if user_role == ResearcherRole.site_admin else 403)
    
    def test_posts_redirect(self):
        # only site admins can load the page
        for user_role in ALL_TESTING_ROLES:
            self.assign_role(self.session_researcher, user_role)
            self.smart_post_status_code(
                302 if user_role == ResearcherRole.site_admin else 403, **self.create_study_params()
            )
    
    def test_create_study_researcher(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        self._test_create_study(False)
    
    def test_create_study_study_admin(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self._test_create_study(False)
    
    def test_create_study_site_admin(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        self._test_create_study(True)
    
    def test_create_study_researcher_and_site_admin(self):
        # unable to replicate hassan's bug - he must have his the special characters bug
        self.set_session_study_relation(ResearcherRole.researcher)
        self.session_researcher.update(site_admin=True)
        self._test_create_study(True)
    
    def test_create_study_study_admin_and_site_admin(self):
        # unable to replicate hassan's bug - he must have his the special characters bug
        self.set_session_study_relation(ResearcherRole.study_admin)
        self.session_researcher.update(site_admin=True)
        self._test_create_study(True)
    
    def _test_create_study(self, success):
        study_count = Study.objects.count()
        device_settings_count = DeviceSettings.objects.count()
        resp = self.smart_post_status_code(302 if success else 403, **self.create_study_params())
        if success:
            self.assertIsInstance(resp, HttpResponseRedirect)
            target_url = easy_url(
                "system_admin_pages.device_settings", study_id=self.get_the_new_study.id
            )
            self.assert_response_url_equal(resp.url, target_url)
            resp = self.client.get(target_url)
            self.assertEqual(resp.status_code, 200)
            self.assert_present(f"Successfully created study {self.get_the_new_study.name}.", resp.content)
            self.assertEqual(study_count + 1, Study.objects.count())
            self.assertEqual(device_settings_count + 1, DeviceSettings.objects.count())
        else:
            self.assertIsInstance(resp, HttpResponse)
            self.assertEqual(study_count, Study.objects.count())
            self.assertEqual(device_settings_count, DeviceSettings.objects.count())
            self.assert_no_new_study
    
    def test_create_study_long_name(self):
        # this situation reports to sentry manually, the response is a hard 400, no calls to messages
        self.set_session_study_relation(ResearcherRole.site_admin)
        params = self.create_study_params()
        params["name"] = "a"*10000
        resp = self.smart_post_status_code(302, **params)
        self.assertEqual(resp.url, easy_url("system_admin_pages.create_study"))
        self.assert_present(
            resp.content, b"the study name you provided was too long and was rejected"
        )
        self.assert_no_new_study
    
    def test_create_study_bad_name(self):
        # this situation reports to sentry manually, the response is a hard 400, no calls to messages
        self.set_session_study_relation(ResearcherRole.site_admin)
        params = self.create_study_params()
        params["name"] = "&" * 50
        resp = self.smart_post_status_code(302, **params)
        self.assert_present(resp.content, b"you provided contained unsafe characters")
        self.assert_no_new_study


# FIXME: this test has the annoying un-factored url with post params and url params
class TestToggleForest(ResearcherSessionTest):
    ENDPOINT_NAME = "system_admin_pages.toggle_study_forest_enabled"
    REDIRECT_ENDPOINT_NAME = "system_admin_pages.edit_study"
    
    def test_toggle_on(self):
        resp = self._do_test_toggle(True)
        self.assert_present("Enabled Forest on", resp.content)
    
    def test_toggle_off(self):
        resp = self._do_test_toggle(False)
        self.assert_present("Disabled Forest on", resp.content)
    
    def _do_test_toggle(self, enable: bool):
        redirect_endpoint = easy_url(self.REDIRECT_ENDPOINT_NAME, study_id=self.session_study.id)
        self.set_session_study_relation(ResearcherRole.site_admin)
        self.session_study.update(forest_enabled=not enable)  # directly mutate the database.
        # resp = self.smart_post(study_id=self.session_study.id)  # nope this does not follow the normal pattern
        resp = self.smart_post(self.session_study.id)
        self.assert_response_url_equal(resp.url, redirect_endpoint)
        self.session_study.refresh_from_db()
        if enable:
            self.assertTrue(self.session_study.forest_enabled)
        else:
            self.assertFalse(self.session_study.forest_enabled)
        return self.client.get(redirect_endpoint)


# FIXME: this test has the annoying un-factored url with post params and url params
class TestDeleteStudy(ResearcherSessionTest):
    ENDPOINT_NAME = "system_admin_pages.delete_study"
    REDIRECT_ENDPOINT_NAME = "system_admin_pages.manage_studies"
    
    def test_success(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        resp = self.smart_post(self.session_study.id, confirmation="true")
        self.session_study.refresh_from_db()
        self.assertTrue(self.session_study.deleted)
        self.assertEqual(resp.url, easy_url(self.REDIRECT_ENDPOINT_NAME))
        self.assert_present("Deleted study ", self.redirect_get_contents())


class TestDeviceSettings(ResearcherSessionTest):
    ENDPOINT_NAME = "system_admin_pages.device_settings"
    
    CONSENT_SECTIONS = {
        'consent_sections.data_gathering.more': 'a',
        'consent_sections.data_gathering.text': 'b',
        'consent_sections.privacy.more': 'c',
        'consent_sections.privacy.text': 'd',
        'consent_sections.study_survey.more': 'e',
        'consent_sections.study_survey.text': 'f',
        'consent_sections.study_tasks.more': 'g',
        'consent_sections.study_tasks.text': 'h',
        'consent_sections.time_commitment.more': 'i',
        'consent_sections.time_commitment.text': 'j',
        'consent_sections.welcome.more': 'k',
        'consent_sections.welcome.text': 'l',
        'consent_sections.withdrawing.more': 'm',
        'consent_sections.withdrawing.text': 'n',
    }
    
    BOOLEAN_FIELD_NAMES = [
        field.name
        for field in DeviceSettings._meta.fields
        if isinstance(field, (models.BooleanField, NullBooleanField))
    ]
    
    def invert_boolean_checkbox_fields(self, some_dict):
        for field in self.BOOLEAN_FIELD_NAMES:
            if field in some_dict and bool(some_dict[field]):
                some_dict.pop(field)
            else:
                some_dict[field] = "true"
    
    def test_get(self):
        for role in ALL_TESTING_ROLES:
            self.assign_role(self.session_researcher, role)
            resp = self.smart_get(self.session_study.id)
            self.assertEqual(resp.status_code, 200 if role is not None else 403)
    
    def test_study_admin(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self.do_test_update()
    
    def test_site_admin(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        self.do_test_update()
    
    def do_test_update(self):
        """ This test mimics the frontend input (checkboxes are a little strange and require setup).
        The test mutates all fields in the input that is sent to the backend, and confirms that every
        field pushed changed. """
        
        # extract data from database (it is all default values, unpacking jsonstrings)
        # created_on and last_updated are already absent
        post_params = self.session_device_settings.export()
        old_device_settings = copy(post_params)
        post_params.pop("id")
        post_params.pop("consent_sections")  # this is not present in the form
        post_params.update(**self.CONSENT_SECTIONS)
        
        # mutate everything
        post_params = {k: self.mutate_variable(v, ignore_bools=True) for k, v in post_params.items()}
        self.invert_boolean_checkbox_fields(post_params)
        
        # Hit endpoint
        self.smart_post_status_code(302, self.session_study.id, **post_params)
        
        # Test database update, get new data, extract consent sections.
        self.assertEqual(DeviceSettings.objects.count(), 1)
        new_device_settings = DeviceSettings.objects.first().export()
        new_device_settings.pop("id")
        old_consent_sections = old_device_settings.pop("consent_sections")
        new_consent_sections = new_device_settings.pop("consent_sections")
        
        for k, v in new_device_settings.items():
            # boolean values are set to true or false based on presence in the post request,
            # that's how checkboxes work.
            if k in self.BOOLEAN_FIELD_NAMES:
                if k not in post_params:
                    self.assertFalse(v)
                    self.assertTrue(old_device_settings[k])
                else:
                    self.assertTrue(v)
                    self.assertFalse(old_device_settings[k])
                continue
            
            # print(f"key: '{k}', DB: {type(v)}'{v}', post param: {type(post_params[k])} '{post_params[k]}'")
            self.assertEqual(v, post_params[k])
            self.assertNotEqual(v, old_device_settings[k])
        
        # FIXME: why does this fail?
        # Consent sections need to be unpacked, ensure they have the keys
        # self.assertEqual(set(old_consent_sections.keys()), set(new_consent_sections.keys()))
        
        for outer_key, a_dict_of_two_values in new_consent_sections.items():
            # this data structure is of the form:  {'more': 'aaaa', 'text': 'baaa'}
            self.assertEqual(len(a_dict_of_two_values), 2)
            
            # compare the inner values of every key, make sure they differ
            for inner_key, v2 in a_dict_of_two_values.items():
                self.assertNotEqual(old_consent_sections[outer_key][inner_key], v2)


class TestChangeSurveySecuritySettings(ResearcherSessionTest):
    ENDPOINT_NAME = "system_admin_pages.change_study_security_settings"
    password_length = len(ResearcherSessionTest.DEFAULT_RESEARCHER_PASSWORD)
    @property
    def DEFAULTS(self):
        """ Default post params, all cause changes to database """
        return {
            "password_minimum_length": "15",
            "password_max_age_enabled": "on",
            "password_max_age_days": "90",
        }
    
    def test_valid_values(self):
        # need to set password length so that we don't crap out at password length of 13 due to a reset
        self.session_researcher.update_only(password_min_length=20)
        self.set_session_study_relation(ResearcherRole.study_admin)
        params = self.DEFAULTS
        
        # test all valid of password length plus 2 invalid values
        for i in range(8, 21):
            params["password_minimum_length"] = i
            self.smart_post_status_code(302, self.session_study.id, **params)
            self.session_study.refresh_from_db()
            self.assertEqual(self.session_study.password_minimum_length, i)
        for i in [0, 7, 21, 1000]:
            params["password_minimum_length"] = i
            self.smart_post_status_code(302, self.session_study.id, **params)
            self.session_study.refresh_from_db()
            self.assertEqual(self.session_study.password_minimum_length, 20)
        
        params["password_minimum_length"] = 15  # reset to something valid so the next test works
        
        # test valid selectable values for password age, then invalid values at the ends
        for i in ["30", "60", "90", "180", "365"]:
            params["password_max_age_days"] = i
            self.smart_post_status_code(302, self.session_study.id, **params)
            self.session_study.refresh_from_db()
            self.assertEqual(self.session_study.password_max_age_days, int(i))
        for i in ["0","29", "366", "1000"]:
            params["password_max_age_days"] = i
            self.smart_post_status_code(302, self.session_study.id, **params)
            self.session_study.refresh_from_db()
            self.assertEqual(self.session_study.password_max_age_days, 365)
    
    def test_missing_all_fields(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self.assertEqual(self.session_researcher.password_min_length, self.password_length)
        self.assertEqual(self.session_study.password_max_age_enabled, False)  # defaults
        self.assertEqual(self.session_study.password_minimum_length, 8)
        self.assertEqual(self.session_study.password_max_age_days, 365)
        ret = self.smart_post_status_code(302, self.session_study.id)
        self.assertEqual(ret.url,
            easy_url("system_admin_pages.study_security_page", self.session_study.id))
        page = self.easy_get("system_admin_pages.study_security_page", study_id=self.session_study.id).content
        
        self.assert_present("Minimum Password Length", page)
        # self.assert_present("Enable Maximum Password Age", page)  # checkboxes do not provide a value if they are unchecked
        self.assert_present("Maximum Password Age (days)", page)
        self.session_study.refresh_from_db()
        # assert no changes
        self.assertEqual(self.session_study.password_max_age_enabled, False)
        self.assertEqual(self.session_study.password_minimum_length, 8)
        self.assertEqual(self.session_study.password_max_age_days, 365)
        self.session_researcher.refresh_from_db()
        self.assertEqual(self.session_researcher.password_force_reset, False)
    
    def test_enable_max_age_enabled(self):
        # set up a bunch of researchers
        r_not_related = self.generate_researcher("not related")
        r_related = self.generate_researcher("researcher")
        r_long = self.generate_researcher("longresearcher")  # won't require password reset
        r_long.set_password("a"*20)
        self.generate_study_relation(r_related, self.session_study, ResearcherRole.researcher)
        self.generate_study_relation(r_long, self.session_study, ResearcherRole.researcher)
        self.assertEqual(self.session_researcher.password_min_length, self.password_length)
        self.assertEqual(r_not_related.password_min_length, self.password_length)
        self.assertEqual(r_related.password_min_length, self.password_length)
        self.assertEqual(r_long.password_min_length, 20)
        # setup and do post
        self.set_session_study_relation(ResearcherRole.study_admin)
        ret = self.smart_post_status_code(302, self.session_study.id, **self.DEFAULTS)
        self.assertEqual(ret.url, easy_url("system_admin_pages.edit_study", self.session_study.id))
        self.session_study.refresh_from_db()
        # assert changes
        self.assertEqual(self.session_study.password_max_age_enabled, True)
        self.assertEqual(self.session_study.password_minimum_length, 15)
        self.assertEqual(self.session_study.password_max_age_days, 90)
        # session researcher should have a password reset
        self.session_researcher.refresh_from_db()
        r_not_related.refresh_from_db()
        r_related.refresh_from_db()
        r_long.refresh_from_db()
        # make sure force reset is not in use, we don't rely on it.
        self.assertEqual(self.session_researcher.password_force_reset, False)
        self.assertEqual(r_related.password_force_reset, False)
        self.assertEqual(r_not_related.password_force_reset, False)
        self.assertEqual(r_long.password_force_reset, False)


class TestEditSurveySecuritySettings(ResearcherSessionTest):
    ENDPOINT_NAME = "system_admin_pages.study_security_page"
    
    def test_researcher(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        self.smart_get_status_code(403, self.session_study.id)
    
    def test_study_admin(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self.smart_get_status_code(200, self.session_study.id)
    
    def test_site_admin(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        self.smart_get_status_code(200, self.session_study.id)


class TestManageFirebaseCredentials(ResearcherSessionTest):
    ENDPOINT_NAME = "system_admin_pages.manage_firebase_credentials"
    
    def test(self):
        # just test that the page loads, I guess
        self.set_session_study_relation(ResearcherRole.site_admin)
        self.smart_get_status_code(200)


# FIXME: implement tests for error cases
class TestUploadBackendFirebaseCert(ResearcherSessionTest):
    ENDPOINT_NAME = "system_admin_pages.upload_backend_firebase_cert"
    REDIRECT_ENDPOINT_NAME = "system_admin_pages.manage_firebase_credentials"
    
    @patch("pages.system_admin_pages.update_firebase_instance")
    @patch("pages.system_admin_pages.get_firebase_credential_errors")
    def test(self, get_firebase_credential_errors: MagicMock, update_firebase_instance: MagicMock):
        # test that the data makes it to the backend, patch out the errors that are sourced from the
        # firbase admin lbrary
        get_firebase_credential_errors.return_value = None
        update_firebase_instance.return_value = True
        # test upload as site admin
        self.set_session_study_relation(ResearcherRole.site_admin)
        file = SimpleUploadedFile("backend_cert.json", BACKEND_CERT.encode(), "text/json")
        self.smart_post(backend_firebase_cert=file)
        resp_content = self.redirect_get_contents()
        self.assert_present("New firebase credentials have been received", resp_content)


# FIXME: implement tests for error cases
class TestUploadIosFirebaseCert(ResearcherSessionTest):
    ENDPOINT_NAME = "system_admin_pages.upload_ios_firebase_cert"
    REDIRECT_ENDPOINT_NAME = "system_admin_pages.manage_firebase_credentials"
    
    def test(self):
        # test upload as site admin
        self.set_session_study_relation(ResearcherRole.site_admin)
        file = SimpleUploadedFile("ios_firebase_cert.plist", IOS_CERT.encode(), "text/json")
        self.smart_post(ios_firebase_cert=file)
        resp_content = self.redirect_get_contents()
        self.assert_present("New IOS credentials were received", resp_content)


# FIXME: implement tests for error cases
class TestUploadAndroidFirebaseCert(ResearcherSessionTest):
    ENDPOINT_NAME = "system_admin_pages.upload_android_firebase_cert"
    REDIRECT_ENDPOINT_NAME = "system_admin_pages.manage_firebase_credentials"
    
    def test(self):
        # test upload as site admin
        self.set_session_study_relation(ResearcherRole.site_admin)
        file = SimpleUploadedFile("android_firebase_cert.json", ANDROID_CERT.encode(), "text/json")
        self.smart_post(android_firebase_cert=file)
        resp_content = self.redirect_get_contents()
        self.assert_present("New android credentials were received", resp_content)


class TestDeleteFirebaseBackendCert(ResearcherSessionTest):
    ENDPOINT_NAME = "system_admin_pages.delete_backend_firebase_cert"
    REDIRECT_ENDPOINT_NAME = "system_admin_pages.manage_firebase_credentials"
    
    def test(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        FileAsText.objects.create(tag=BACKEND_FIREBASE_CREDENTIALS, text="any_string")
        self.smart_post()
        self.assertFalse(FileAsText.objects.exists())


class TestDeleteFirebaseIosCert(ResearcherSessionTest):
    ENDPOINT_NAME = "system_admin_pages.delete_ios_firebase_cert"
    REDIRECT_ENDPOINT_NAME = "system_admin_pages.manage_firebase_credentials"
    
    def test(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        FileAsText.objects.create(tag=IOS_FIREBASE_CREDENTIALS, text="any_string")
        self.smart_post()
        self.assertFalse(FileAsText.objects.exists())


class TestDeleteFirebaseAndroidCert(ResearcherSessionTest):
    ENDPOINT_NAME = "system_admin_pages.delete_android_firebase_cert"
    REDIRECT_ENDPOINT_NAME = "system_admin_pages.manage_firebase_credentials"
    
    def test(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        FileAsText.objects.create(tag=ANDROID_FIREBASE_CREDENTIALS, text="any_string")
        self.smart_post()
        self.assertFalse(FileAsText.objects.exists())


# FIXME: add error cases to this test
class TestSetStudyTimezone(ResearcherSessionTest):
    ENDPOINT_NAME = "admin_api.set_study_timezone"
    REDIRECT_ENDPOINT_NAME = "system_admin_pages.edit_study"
    
    def test_study_admin(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self._test_success()
    
    def test_site_admin(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        self._test_success()
    
    def _test_success(self):
        self.smart_post(self.session_study.id, new_timezone_name="Pacific/Noumea")
        self.session_study.refresh_from_db()
        self.assertEqual(self.session_study.timezone_name, "Pacific/Noumea")


class TestAddResearcherToStudy(ResearcherSessionTest):
    ENDPOINT_NAME = "admin_api.add_researcher_to_study"
    REDIRECT_ENDPOINT_NAME = "system_admin_pages.edit_study"
    
    def test_site_admin(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        self._test(None, 302, ResearcherRole.researcher)
        self._test(ResearcherRole.study_admin, 302, ResearcherRole.study_admin)
        self._test(ResearcherRole.researcher, 302, ResearcherRole.researcher)
    
    # # FIXME: test fails, need to fix data download bug on site admin users first
    # def test_site_admin_on_site_admin(self):
    #     self.set_session_study_relation(ResearcherRole.site_admin)
    #     self._test(ResearcherRole.site_admin, 403, ResearcherRole.site_admin)
    
    def test_study_admin_on_none(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self._test(None, 302, ResearcherRole.researcher)
    
    def test_study_admin_on_study_admin(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self._test(ResearcherRole.study_admin, 302, ResearcherRole.study_admin)
    
    def test_study_admin_on_researcher(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self._test(ResearcherRole.researcher, 302, ResearcherRole.researcher)
    
    # FIXME: test fails, need to fix data download bug on site admin users first
    # def test_study_admin_on_site_admin(self):
    #     self.set_session_study_relation(ResearcherRole.study_admin)
    #     self._test(ResearcherRole.site_admin, 403, ResearcherRole.site_admin)
    
    def test_researcher(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        self._test(ResearcherRole.researcher, 403, ResearcherRole.researcher)
        self._test(ResearcherRole.study_admin, 403, ResearcherRole.study_admin)
        self._test(None, 403, None)
        self._test(ResearcherRole.site_admin, 403, ResearcherRole.site_admin)
    
    def _test(self, r2_starting_relation, status_code, desired_relation):
        # setup researcher, do the post request
        r2 = self.generate_researcher(relation_to_session_study=r2_starting_relation)
        redirect_or_response = self.smart_post(
            study_id=self.session_study.id,
            researcher_id=r2.id,
            redirect_url=f"/edit_study/{self.session_study.id}"
        )
        # check status code, relation, and ~the redirect url.
        r2.refresh_from_db()
        self.assert_researcher_relation(r2, self.session_study, desired_relation)
        self.assertEqual(redirect_or_response.status_code, status_code)
        if isinstance(redirect_or_response, HttpResponseRedirect):
            self.assertEqual(redirect_or_response.url, f"/edit_study/{self.session_study.id}")


#
## data_access_web_form
#
class TestDataAccessWebFormPage(ResearcherSessionTest):
    ENDPOINT_NAME = "data_access_web_form.data_api_web_form_page"
    
    def test(self):
        resp = self.smart_get()
        self.assert_present("Reset Data-Download API Access Credentials", resp.content)
        id_key, secret_key = self.session_researcher.reset_access_credentials()
        resp = self.smart_get()
        self.assert_not_present("Reset Data-Download API Access Credentials", resp.content)

#
## admin_api
#
class TestRemoveResearcherFromStudy(ResearcherSessionTest):
    ENDPOINT_NAME = "admin_api.remove_researcher_from_study"
    REDIRECT_ENDPOINT_NAME = "system_admin_pages.edit_study"
    
    def test_site_admin(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        self._test(None, 302)
        self._test(ResearcherRole.study_admin, 302)
        self._test(ResearcherRole.researcher, 302)
        self._test(ResearcherRole.site_admin, 302)
    
    def test_study_admin(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self._test(None, 403)
        self._test(ResearcherRole.study_admin, 403)
        self._test(ResearcherRole.researcher, 302)
        self._test(ResearcherRole.site_admin, 403)
    
    def test_researcher(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        r2 = self.generate_researcher(relation_to_session_study=None)
        self.smart_post_status_code(
            403,
            study_id=self.session_study.id,
            researcher_id=r2.id,
            redirect_url=f"/edit_study/{self.session_study.id}"
        )
    
    def _test(self, r2_starting_relation, status_code):
        if r2_starting_relation == ResearcherRole.site_admin:
            r2 = self.generate_researcher(relation_to_session_study=ResearcherRole.site_admin)
        else:
            r2 = self.generate_researcher(relation_to_session_study=r2_starting_relation)
        redirect = self.smart_post(
            study_id=self.session_study.id,
            researcher_id=r2.id,
            redirect_url=f"/edit_study/{self.session_study.id}"
        )
        # needs to be a None at the end
        self.assertEqual(redirect.status_code, status_code)
        if isinstance(redirect, HttpResponseRedirect):
            self.assert_researcher_relation(r2, self.session_study, None)
            self.assertEqual(redirect.url, f"/edit_study/{self.session_study.id}")


class TestDeleteResearcher(ResearcherSessionTest):
    ENDPOINT_NAME = "admin_api.delete_researcher"
    
    def test_site_admin(self):
        self._test_basics(302, ResearcherRole.site_admin, True)
    
    def test_study_admin(self):
        self._test_basics(403, ResearcherRole.study_admin, False)
    
    def test_researcher(self):
        self._test_basics(403, ResearcherRole.researcher, False)
    
    def test_no_relation(self):
        self._test_basics(403, None, False)
    
    def test_nonexistent(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        # 0 is not a valid database key.
        self.smart_get_status_code(404, 0)
    
    def _test_basics(self, status_code: int, relation: str, success: bool):
        self.set_session_study_relation(relation)  # implicitly creates self.session_researcher
        r2 = self.generate_researcher()
        self.smart_get_status_code(status_code, r2.id)
        self.assertEqual(Researcher.objects.filter(id=r2.id).count(), 0 if success else 1)
    
    def test_cascade(self):
        # first assert that this is actually all the relations:
        self.assertEqual(
            [obj.related_model.__name__ for obj in Researcher._meta.related_objects],
            ['StudyRelation', 'ResearcherSession', 'DataAccessRecord', 'ApiKey']
        )
        # we need the test to succeed...
        self.set_session_study_relation(ResearcherRole.site_admin)
        r2 = self.generate_researcher()
        
        # generate all possible researcher relations for r2 as determined above:
        ApiKey.generate(researcher=r2, has_tableau_api_permissions=True, readable_name="test_api_key")
        relation_id = self.generate_study_relation(r2, self.default_study, ResearcherRole.researcher).id
        record = DataAccessRecord.objects.create(researcher=r2, query_params="test_junk", username=r2.username)
        # for tests after deletion
        relation_id = r2.study_relations.get().id
        default_study_id = self.default_study.id
        # request
        self.smart_get_status_code(302, r2.id)
        # test that these were deleted
        self.assertFalse(Researcher.objects.filter(id=r2.id).exists())
        self.assertFalse(ApiKey.objects.exists())
        self.assertFalse(StudyRelation.objects.filter(id=relation_id).exists())
        # I can never remember the direction of cascade, confirm study is still there
        self.assertTrue(Study.objects.filter(id=default_study_id).exists())
        # and assert that the DataAccessRecord is still there with a null researcher and a username.
        self.assertTrue(DataAccessRecord.objects.filter(id=record.id).exists())
        record.refresh_from_db()
        self.assertIsNone(record.researcher)
        self.assertEqual(record.username, r2.username)


class TestSetResearcherPassword(ResearcherSessionTest):
    ENDPOINT_NAME = "admin_api.set_researcher_password"
    
    def test_site_admin_on_a_null_user(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        r2 = self.generate_researcher()
        self._test_successful_change(r2)
    
    def test_site_admin_on_researcher(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        r2 = self.generate_researcher()
        self.generate_study_relation(r2, self.default_study, ResearcherRole.researcher)
        self._test_successful_change(r2)
    
    def test_site_admin_on_study_admin(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        r2 = self.generate_researcher()
        self.generate_study_relation(r2, self.default_study, ResearcherRole.study_admin)
        self._test_successful_change(r2)
    
    def test_site_admin_on_site_admin(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        r2 = self.generate_researcher()
        self.generate_study_relation(r2, self.default_study, ResearcherRole.site_admin)
        self._test_cannot_change(r2, PASSWORD_RESET_FAIL_SITE_ADMIN)
    
    def _test_successful_change(self, r2: Researcher):
        self.smart_post(
            researcher_id=r2.id,
            password=self.DEFAULT_RESEARCHER_PASSWORD + "1",
        )
        # we are ... teleologically correct here mimicking the code...
        r2.refresh_from_db()
        self.assertTrue(r2.password_force_reset)
        self.assertTrue(
            r2.check_password(r2.username, self.DEFAULT_RESEARCHER_PASSWORD + "1")
        )
        self.assertFalse(
            r2.check_password(r2.username, self.DEFAULT_RESEARCHER_PASSWORD)
        )
        self.assertEqual(r2.web_sessions.count(), 0)
    
    def _test_cannot_change(self, r2: Researcher, message: str = None):
        ret = self.smart_post(
            researcher_id=r2.id,
            password=self.DEFAULT_RESEARCHER_PASSWORD + "1",
        )
        if message:
            content = self.easy_get("system_admin_pages.edit_researcher", researcher_pk=r2.id).content
            self.assert_present(message, content)
        r2.refresh_from_db()
        self.assertFalse(r2.password_force_reset)
        self.assertFalse(
            r2.check_password(r2.username, self.DEFAULT_RESEARCHER_PASSWORD + "1")
        )
        self.assertTrue(
            r2.check_password(r2.username, self.DEFAULT_RESEARCHER_PASSWORD)
        )
        self.assertEqual(self.session_researcher.web_sessions.count(), 1)
        return ret


class TestToggleStudyEasyEnrollment(ResearcherSessionTest):
    ENDPOINT_NAME = "admin_api.toggle_easy_enrollment_study"
    REDIRECT_ENDPOINT_NAME = "system_admin_pages.edit_study"
    
    def test_site_admin(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        self._test_success()
    
    def test_study_admin(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self._test_success()
    
    def _test_success(self):
        self.assertFalse(self.default_study.easy_enrollment)
        self.smart_get_redirect(self.session_study.id)
        self.default_study.refresh_from_db()
        self.assertTrue(self.default_study.easy_enrollment)
    
    def test_researcher(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        self._test_fail()
    
    def test_no_relation(self):
        self.session_researcher.study_relations.all().delete()  # should be redundant
        self._test_fail()
    
    def _test_fail(self):
        self.assertFalse(self.default_study.easy_enrollment)
        self.easy_get(self.ENDPOINT_NAME, status_code=403, study_id=self.session_study.id).content
        self.default_study.refresh_from_db()
        self.assertFalse(self.default_study.easy_enrollment)


# fixme: add user type tests
class TestRenameStudy(ResearcherSessionTest):
    ENDPOINT_NAME = "admin_api.rename_study"
    REDIRECT_ENDPOINT_NAME = "system_admin_pages.edit_study"
    
    def test(self):
        self.set_session_study_relation(ResearcherRole.site_admin)
        self.smart_post_redirect(self.session_study.id, new_study_name="hello!")
        self.session_study.refresh_from_db()
        self.assertEqual(self.session_study.name, "hello!")


class TestPrivacyPolicy(ResearcherSessionTest):
    ENDPOINT_NAME = "admin_api.download_privacy_policy"
    
    def test(self):
        # just test that it loads without breaking
        redirect = self.smart_get()
        self.assertIsInstance(redirect, HttpResponseRedirect)

#
## study_api
#

# FIXME: implement this test beyond "it doesn't crash"
class TestStudyParticipantApi(ResearcherSessionTest):
    ENDPOINT_NAME = "study_api.study_participants_api"
    
    COLUMN_ORDER_KEY = "order[0][column]"
    ORDER_DIRECTION_KEY = "order[0][dir]"
    SEARCH_PARAMETER = "search[value]"
    SOME_TIMESTAMP = timezone.make_aware(datetime(2020, 10, 1))
    
    # This endpoint is stupidly complex, it implements pagination, sorting, search ordering.
    
    @property
    def DEFAULT_PARAMETERS(self):
        # you need to be at least a researcher, factor out this clutter
        self.set_session_study_relation(ResearcherRole.researcher)
        return {
            "draw": 1,
            "start": 0,
            "length": 10,
            # sort, sort order, search term.  order key is index into this list, larger values
            # target first interventions then custom fields:
            # ['created_on', 'patient_id', 'registered', 'os_type']
            self.COLUMN_ORDER_KEY: 0,
            self.ORDER_DIRECTION_KEY: "asc",
            self.SEARCH_PARAMETER: "",
        }
    
    @property
    def DEFAULT_RESPONSE(self):
        return {
            "draw": 1,
            "recordsTotal": 1,
            "recordsFiltered": 1,
            "data": [[self.SOME_TIMESTAMP.strftime(API_DATE_FORMAT),
                      self.default_participant.patient_id,
                      True,
                      "ANDROID"]]
        }
    
    def test_basics(self):
        # manually set the created on timestamp... its a pain to set and a pain to test.
        self.default_participant.update_only(created_on=self.SOME_TIMESTAMP)
        # this endpoint uses get args, for which we have to pass in the dict as the "data" kwarg
        resp = self.smart_post_status_code(200, self.session_study.id, **self.DEFAULT_PARAMETERS)
        content = json.loads(resp.content.decode())
        self.assertEqual(content, self.DEFAULT_RESPONSE)
    
    def test_with_intervention(self):
        self.default_participant.update_only(created_on=self.SOME_TIMESTAMP)
        # need to populate some database state, this database stat is expected to be populated when
        # a participant is created and/or when an intervention is created.
        self.default_intervention
        self.default_populated_intervention_date
        resp = self.smart_post_status_code(200, self.session_study.id, **self.DEFAULT_PARAMETERS)
        content = json.loads(resp.content.decode())
        correct_content = self.DEFAULT_RESPONSE
        correct_content["data"][0].append(self.CURRENT_DATE.strftime(API_DATE_FORMAT))  # the value populated in the intervention date
        self.assertEqual(content, correct_content)
    
    def test_with_custom_field(self):
        self.default_participant.update_only(created_on=self.SOME_TIMESTAMP)
        self.default_participant_field_value  # populate database state
        resp = self.smart_post_status_code(200, self.session_study.id, **self.DEFAULT_PARAMETERS)
        content = json.loads(resp.content.decode())
        correct_content = self.DEFAULT_RESPONSE
        correct_content["data"][0].append(self.DEFAULT_PARTICIPANT_FIELD_VALUE)  # default value
        self.assertEqual(content, correct_content)
    
    def test_with_both(self):
        self.default_participant.update_only(created_on=self.SOME_TIMESTAMP)
        self.default_intervention  # populate database state
        self.default_populated_intervention_date
        self.default_participant_field_value
        resp = self.smart_post_status_code(200, self.session_study.id, **self.DEFAULT_PARAMETERS)
        content = json.loads(resp.content.decode())
        correct_content = self.DEFAULT_RESPONSE
        correct_content["data"][0].append(self.CURRENT_DATE.strftime(API_DATE_FORMAT))
        correct_content["data"][0].append(self.DEFAULT_PARTICIPANT_FIELD_VALUE)
        self.assertEqual(content, correct_content)
    
    def test_simple_ordering(self):
        # setup default participant
        self.default_participant.update_only(created_on=self.SOME_TIMESTAMP)
        self.default_intervention
        self.default_populated_intervention_date
        self.default_participant_field_value
        # setup second participant
        p2 = self.generate_participant(self.session_study, "patient2")
        p2.update_only(created_on=self.SOME_TIMESTAMP + timedelta(days=1))  # for sorting
        self.generate_intervention_date(p2, self.default_intervention, None)  # correct db population
        # construct the correct response data (yuck)
        correct_content = self.DEFAULT_RESPONSE
        correct_content["recordsTotal"] = 2
        correct_content["recordsFiltered"] = 2
        correct_content["data"][0].append(self.CURRENT_DATE.strftime(API_DATE_FORMAT))
        correct_content["data"][0].append(self.DEFAULT_PARTICIPANT_FIELD_VALUE)
        # created on, patient id, registered, os_type, intervention date, custom field
        # (registered is based on presence of os_type)
        correct_content["data"].append([
            p2.created_on.strftime(API_DATE_FORMAT), p2.patient_id, True, "ANDROID", "", ""
        ])
        # request, compare
        params = self.DEFAULT_PARAMETERS
        resp = self.smart_post_status_code(200, self.session_study.id, **params)
        content = json.loads(resp.content.decode())
        self.assertEqual(content, correct_content)
        # reverse the order
        params[self.ORDER_DIRECTION_KEY] = "desc"
        correct_content["data"].append(correct_content["data"].pop(0))  # swap 2 rows
        resp = self.smart_post_status_code(200, self.session_study.id, **params)
        content = json.loads(resp.content.decode())
        self.assertEqual(content, correct_content)


class TestInterventionsPage(ResearcherSessionTest):
    ENDPOINT_NAME = "study_api.interventions_page"
    REDIRECT_ENDPOINT_NAME = "study_api.interventions_page"
    
    def test_get(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self.generate_intervention(self.session_study, "obscure_name_of_intervention")
        resp = self.smart_get(self.session_study.id)
        self.assert_present("obscure_name_of_intervention", resp.content)
    
    def test_post(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        resp = self.smart_post(self.session_study.id, new_intervention="ohello")
        self.assertEqual(resp.status_code, 302)
        intervention = Intervention.objects.get(study=self.session_study)
        self.assertEqual(intervention.name, "ohello")


class TestDeleteIntervention(ResearcherSessionTest):
    ENDPOINT_NAME = "study_api.delete_intervention"
    REDIRECT_ENDPOINT_NAME = "study_api.interventions_page"
    
    def test(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        intervention = self.generate_intervention(self.session_study, "obscure_name_of_intervention")
        self.smart_post_redirect(self.session_study.id, intervention=intervention.id)
        self.assertFalse(Intervention.objects.filter(id=intervention.id).exists())


class TestEditIntervention(ResearcherSessionTest):
    ENDPOINT_NAME = "study_api.edit_intervention"
    REDIRECT_ENDPOINT_NAME = "study_api.interventions_page"
    
    def test(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        intervention = self.generate_intervention(self.session_study, "obscure_name_of_intervention")
        self.smart_post_redirect(
            self.session_study.id, intervention_id=intervention.id, edit_intervention="new_name"
        )
        intervention_new = Intervention.objects.get(id=intervention.id)
        self.assertEqual(intervention.id, intervention_new.id)
        self.assertEqual(intervention_new.name, "new_name")


class TestStudyFields(ResearcherSessionTest):
    ENDPOINT_NAME = "study_api.study_fields"
    REDIRECT_ENDPOINT_NAME = "study_api.study_fields"
    
    def test_get(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self.generate_study_field(self.session_study, "obscure_name_of_study_field")
        # This isn't a pure redirect endpoint, we need get to have a 200
        resp = self.smart_get(self.session_study.id)
        self.assertEqual(resp.status_code, 200)
        self.assert_present("obscure_name_of_study_field", resp.content)
    
    def test_post(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        resp = self.smart_post_redirect(self.session_study.id, new_field="ohello")
        self.assertEqual(resp.status_code, 302)
        study_field = StudyField.objects.get(study=self.session_study)
        self.assertEqual(study_field.field_name, "ohello")


class TestDeleteStudyField(ResearcherSessionTest):
    ENDPOINT_NAME = "study_api.delete_field"
    REDIRECT_ENDPOINT_NAME = "study_api.study_fields"
    
    def test(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        study_field = self.generate_study_field(self.session_study, "obscure_name_of_study_field")
        self.smart_post_redirect(self.session_study.id, field=study_field.id)
        self.assertFalse(StudyField.objects.filter(id=study_field.id).exists())


class TestEditStudyField(ResearcherSessionTest):
    ENDPOINT_NAME = "study_api.edit_custom_field"
    REDIRECT_ENDPOINT_NAME = "study_api.study_fields"
    
    def test(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        study_field = self.generate_study_field(self.session_study, "obscure_name_of_study_field")
        self.smart_post_redirect(
            self.session_study.id, field_id=study_field.id, edit_custom_field="new_name"
        )
        study_field_new = StudyField.objects.get(id=study_field.id)
        self.assertEqual(study_field.id, study_field_new.id)
        self.assertEqual(study_field_new.field_name, "new_name")

#
## participant_pages
#

# FIXME: implement more tests of this endpoint, it is complex.
class TestNotificationHistory(ResearcherSessionTest):
    ENDPOINT_NAME = "participant_pages.notification_history"
    
    def test(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        self.generate_archived_event(self.default_survey, self.default_participant)
        self.smart_get_status_code(200, self.session_study.id, self.default_participant.patient_id)


class TestParticipantPage(ResearcherSessionTest):
    ENDPOINT_NAME = "participant_pages.participant_page"
    REDIRECT_ENDPOINT_NAME = "participant_pages.participant_page"
    
    def test_get(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        # This isn't a pure redirect endpoint, we need to test for a 200
        self.easy_get(
            self.ENDPOINT_NAME, status_code=200,
            study_id=self.session_study.id, patient_id=self.default_participant.patient_id)
    
    def test_post_with_bad_parameters(self):
        # test bad study id and bad patient id
        self.set_session_study_relation(ResearcherRole.study_admin)
        ret = self.smart_post(self.session_study.id, "invalid_patient_id")
        self.assertEqual(ret.status_code, 404)
        ret = self.smart_post(0, self.default_participant.patient_id)
        self.assertEqual(ret.status_code, 404)
    
    def test_custom_field_update(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        study_field = self.generate_study_field(self.session_study, "obscure_name_of_study_field")
        # intervention_date = self.default_unpopulated_intervention_date  # create a single intervention with no time
        self.assertFalse(self.default_participant.field_values.exists())
        
        # the post parameter here is  bit strange, literally it is like "field6" with a db pk
        post_param_name = "field" + str(study_field.id)
        self.smart_post_redirect(self.session_study.id, self.default_participant.patient_id,
            **{post_param_name: "any string value"})
        self.assertEqual(self.default_participant.field_values.count(), 1)
        field_value = self.default_participant.field_values.first()
        self.assertEqual(field_value.field, study_field)
        self.assertEqual(field_value.value, "any string value")
    
    def test_intervention_update(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        intervention_date = self.default_unpopulated_intervention_date  # create a single intervention with no time
        self.assertEqual(intervention_date.date, None)
        # the post parameter here is  bit strange, literally it is like "intervention6" with a db pk
        post_param_name = "intervention" + str(intervention_date.intervention.id)
        self.smart_post_redirect(self.session_study.id, self.default_participant.patient_id,
            **{post_param_name: "2020-01-01"})
        intervention_date.refresh_from_db()
        self.assertEqual(intervention_date.date, date(2020, 1, 1))
    
    def test_bad_date_1(self):
        self._test_intervention_update_with_bad_date("2020/01/01")
    
    def test_bad_date_2(self):
        self._test_intervention_update_with_bad_date("31/01/2020")
    
    def test_bad_date_3(self):
        self._test_intervention_update_with_bad_date("01/31/2020")
    
    def _test_intervention_update_with_bad_date(self, date_string: str):
        self.set_session_study_relation(ResearcherRole.study_admin)
        intervention_date = self.default_unpopulated_intervention_date  # create a single intervention with no time
        self.assertEqual(intervention_date.date, None)
        # the post parameter here is  bit strange, literally it is like "intervention6" with a db pk
        post_param_name = "intervention" + str(intervention_date.intervention.id)
        self.smart_post_redirect(self.session_study.id, self.default_participant.patient_id,
            **{post_param_name: date_string})
        intervention_date.refresh_from_db()
        self.assertEqual(intervention_date.date, None)
        page = self.easy_get(
            self.ENDPOINT_NAME, status_code=200,
            study_id=self.session_study.id, patient_id=self.default_participant.patient_id).content
        self.assert_present(
            'Invalid date format, please use the date selector or YYYY-MM-DD.', page
        )

#
## copy_study_api
#

# FIXME: add interventions and surveys to the export tests
class TestExportStudySettingsFile(ResearcherSessionTest):
    ENDPOINT_NAME = "copy_study_api.export_study_settings_file"
    
    def test(self):
        self.set_session_study_relation(ResearcherRole.study_admin)
        # FileResponse objects stream, which means you need to iterate over `resp.streaming_content``
        resp: FileResponse = self.smart_get(self.session_study.id)
        # sanity check...
        items_to_iterate = 0
        for file_bytes in resp.streaming_content:
            items_to_iterate += 1
        self.assertEqual(items_to_iterate, 1)
        # get survey, check device_settings, surveys, interventions are all present
        output_survey: dict = json.loads(file_bytes.decode())  # make sure it is a json file
        self.assertIn("device_settings", output_survey)
        self.assertIn("surveys", output_survey)
        self.assertIn("interventions", output_survey)
        output_device_settings: dict = output_survey["device_settings"]
        real_device_settings = self.session_device_settings.export()
        # confirm that all elements are equal for the dicts
        for k, v in output_device_settings.items():
            self.assertEqual(v, real_device_settings[k])


# FIXME: add interventions and surveys to the import tests
class TestImportStudySettingsFile(ResearcherSessionTest):
    ENDPOINT_NAME = "copy_study_api.import_study_settings_file"
    REDIRECT_ENDPOINT_NAME = "system_admin_pages.edit_study"
    
    # other post params: device_settings, surveys
    
    def test_no_device_settings_no_surveys(self):
        content = self._test(False, False)
        self.assert_present("Did not alter", content)
        self.assert_present("Copied 0 Surveys and 0 Audio Surveys", content)
    
    def test_device_settings_no_surveys(self):
        content = self._test(True, False)
        self.assert_present("Settings with custom values.", content)
        self.assert_present("Copied 0 Surveys and 0 Audio Surveys", content)
    
    def test_device_settings_and_surveys(self):
        content = self._test(True, True)
        self.assert_present("Settings with custom values.", content)
        self.assert_present("Copied 0 Surveys and 0 Audio Surveys", content)
    
    def test_bad_filename(self):
        content = self._test(True, True, ".exe", success=False)
        # FIXME: this is not present in the html, it should be  - string doesn't appear in codebase...
        # self.assert_present("You can only upload .json files.", content)
    
    def _test(
        self, device_settings: bool, surveys: bool, extension: str = "json", success: bool = True
    ) -> bytes:
        self.set_session_study_relation(ResearcherRole.site_admin)
        study2 = self.generate_study("study_2")
        self.assertEqual(self.session_device_settings.gps, True)
        self.session_device_settings.update(gps=False)
        
        # this is the function that creates the canonical study representation wrapped in a burrito
        survey_json_file = BytesIO(format_study(self.session_study).encode())
        survey_json_file.name = f"something.{extension}"  # ayup, that's how you add a name...
        
        self.smart_post_redirect(
            study2.id,
            upload=survey_json_file,
            device_settings="true" if device_settings else "false",
            surveys="true" if surveys else "false",
        )
        study2.device_settings.refresh_from_db()
        if success:
            self.assertEqual(study2.device_settings.gps, not device_settings)
        # return the page, we always need it
        return self.easy_get(self.REDIRECT_ENDPOINT_NAME, status_code=200, study_id=study2.id).content


#
## survey_api
#

class TestICreateSurvey(ResearcherSessionTest):
    ENDPOINT_NAME = "survey_api.create_survey"
    REDIRECT_ENDPOINT_NAME = "survey_designer.render_edit_survey"
    
    def test_tracking(self):
        self._test(Survey.TRACKING_SURVEY)
    
    def test_audio(self):
        self._test(Survey.AUDIO_SURVEY)
    
    def test_image(self):
        self._test(Survey.IMAGE_SURVEY)
    
    def _test(self, survey_type: str):
        self.set_session_study_relation(ResearcherRole.researcher)
        self.assertEqual(Survey.objects.count(), 0)
        resp = self.smart_get_redirect(self.session_study.id, survey_type)
        self.assertEqual(resp.status_code, 302)
        self.assertEqual(Survey.objects.count(), 1)
        survey: Survey = Survey.objects.get()
        self.assertEqual(survey_type, survey.survey_type)


# FIXME: add schedule removal tests to this test
class TestDeleteSurvey(ResearcherSessionTest):
    ENDPOINT_NAME = "survey_api.delete_survey"
    REDIRECT_ENDPOINT_NAME = "admin_pages.view_study"
    
    def test(self):
        self.assertEqual(Survey.objects.count(), 0)
        self.set_session_study_relation(ResearcherRole.researcher)
        survey = self.generate_survey(self.session_study, Survey.TRACKING_SURVEY)
        self.assertEqual(Survey.objects.count(), 1)
        self.smart_post_redirect(self.session_study.id, survey.id)
        self.assertEqual(Survey.objects.count(), 1)
        self.assertEqual(Survey.objects.filter(deleted=False).count(), 0)


# FIXME: implement more details of survey object updates
class TestUpdateSurvey(ResearcherSessionTest):
    ENDPOINT_NAME = "survey_api.update_survey"
    
    def test_with_hax_to_bypass_the_hard_bit(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        survey = self.generate_survey(self.session_study, Survey.TRACKING_SURVEY)
        self.assertEqual(survey.settings, '{}')
        resp = self.smart_post(
            self.session_study.id, survey.id, content='[]', settings='[]',
            weekly_timings='[]', absolute_timings='[]', relative_timings='[]',
        )
        survey.refresh_from_db()
        self.assertEqual(survey.settings, '[]')
        self.assertEqual(resp.status_code, 201)


#
## survey_designer
#

# FIXME: add interventions and survey schedules
class TestRenderEditSurvey(ResearcherSessionTest):
    ENDPOINT_NAME = "survey_designer.render_edit_survey"
    
    def test(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        survey = self.generate_survey(self.session_study, Survey.TRACKING_SURVEY)
        self.smart_get_status_code(200, self.session_study.id, survey.id)


#
## participant_administration
#

class TestDeleteParticipant(ResearcherSessionTest):
    ENDPOINT_NAME = "participant_administration.delete_participant"
    REDIRECT_ENDPOINT_NAME = "participant_pages.participant_page"
    
    # most of this was copy-pasted from TestUnregisterParticipant, which was copied from TestResetDevice
    
    def test_bad_study_id(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        resp = self.smart_post(patient_id=self.default_participant.patient_id, study_id=0)
        self.assertEqual(resp.status_code, 404)
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.is_dead, False)
    
    def test_wrong_study_id(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        study2 = self.generate_study("study2")
        self.generate_study_relation(self.session_researcher, study2, ResearcherRole.researcher)
        self.smart_post_redirect(patient_id=self.default_participant.patient_id, study_id=study2.id)
        self.assert_present(
            "is not in study",
            self.redirect_get_contents(patient_id=self.default_participant.patient_id, study_id=study2.id)
        )
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.is_dead, False)
    
    def test_bad_participant(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        self.smart_post_redirect(patient_id="invalid", study_id=self.session_study.id)
        self.assert_present(
            "does not exist",
            self.easy_get("admin_pages.view_study", status_code=200, study_id=self.session_study.id).content
        )
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.is_dead, False)
    
    def test_participant_already_queued(self):
        ParticipantDeletionEvent.objects.create(participant=self.default_participant)
        self.set_session_study_relation(ResearcherRole.researcher)
        self.smart_post_redirect(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        page = self.redirect_get_contents(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        self.assert_present(
            PARTICIPANT_LOCKED.format(patient_id=self.default_participant.patient_id), page
        )
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.is_dead, True)
        self.assertEqual(self.default_participant.has_deletion_event, True)
        self.assertEqual(self.default_participant.deleted, False)
        self.assertEqual(ParticipantDeletionEvent.objects.count(), 1)
    
    def test_success(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        self._test_success()
    
    def _test_success(self):
        self.assertEqual(self.default_participant.is_dead, False)
        self.assertEqual(self.default_participant.has_deletion_event, False)
        self.assertEqual(self.default_participant.deleted, False)
        self.assertEqual(ParticipantDeletionEvent.objects.count(), 0)
        
        self.smart_post_redirect(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        page = self.redirect_get_contents(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.is_dead, True)
        self.assertEqual(self.default_participant.has_deletion_event, True)
        self.assertEqual(self.default_participant.deleted, False)
        self.assertEqual(ParticipantDeletionEvent.objects.count(), 1)
        self.assert_present(
            PARTICIPANT_LOCKED.format(patient_id=self.default_participant.patient_id), page
        )
        self.assert_present(  # assert page component isn't present
            "This action deletes all data that this participant has ever uploaded", page
        )
    
    # look the feature works and these tests are overkill, okay?
    def test_relation_restriction_researcher(self):
        p1, p2 = self.get_patches([ResearcherRole.study_admin])
        with p1, p2:
            self.set_session_study_relation(ResearcherRole.researcher)
            self._test_relation_restriction_failure()
    
    def test_relation_restriction_site_admin(self):
        p1, p2 = self.get_patches([ResearcherRole.site_admin])
        with p1, p2:
            self.set_session_study_relation(ResearcherRole.study_admin)
            self._test_relation_restriction_failure()
    
    def test_relation_restriction_site_admin_works_just_site_admins(self):
        p1, p2 = self.get_patches([ResearcherRole.site_admin])
        with p1, p2:
            self.set_session_study_relation(ResearcherRole.site_admin)
            self._test_success()
    
    def test_relation_restriction_site_admin_works_researcher(self):
        p1, p2 = self.get_patches([ResearcherRole.study_admin, ResearcherRole.researcher])
        with p1, p2:
            self.set_session_study_relation(ResearcherRole.site_admin)
            self._test_success()
    
    def test_relation_restriction_site_admin_works_study_admin(self):
        p1, p2 = self.get_patches([ResearcherRole.study_admin, ResearcherRole.researcher])
        with p1, p2:
            self.set_session_study_relation(ResearcherRole.site_admin)
            self._test_success()
    
    def test_relation_restriction_study_admin_works_researcher(self):
        p1, p2 = self.get_patches([ResearcherRole.study_admin, ResearcherRole.researcher])
        with p1, p2:
            self.set_session_study_relation(ResearcherRole.study_admin)
            self._test_success()
    
    def get_patches(self, the_patch):
        from api import participant_administration
        from pages import participant_pages
        return (
            patch.object(participant_pages, "DATA_DELETION_ALLOWED_RELATIONS", the_patch),
            patch.object(participant_administration, "DATA_DELETION_ALLOWED_RELATIONS", the_patch),
        )
    
    def _test_relation_restriction_failure(self):
        self.smart_post_redirect(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        page = self.redirect_get_contents(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        self.assert_not_present(  # assert page component isn't present
            "This action deletes all data that this participant has ever uploaded", page
        )
        self.assert_not_present(  # assert normal error Didn't happen
            PARTICIPANT_LOCKED.format(patient_id=self.default_participant.patient_id), page
        )
        self.assert_present(  # assert specific error Did happen
            NO_DELETION_PERMISSION.format(patient_id=self.default_participant.patient_id), page
        )
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.is_dead, False)
        self.assertEqual(self.default_participant.has_deletion_event, False)
        self.assertEqual(self.default_participant.deleted, False)
        self.assertEqual(ParticipantDeletionEvent.objects.count(), 0)
    
    def test_deleted_participant(self):
        self.default_participant.update(unregistered=False, deleted=True)
        self.set_session_study_relation(ResearcherRole.researcher)
        self.smart_post_redirect(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        page = self.redirect_get_contents(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        self.assert_present(
            PARTICIPANT_LOCKED.format(patient_id=self.default_participant.patient_id), page
        )
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.is_dead, True)
        self.assertEqual(self.default_participant.has_deletion_event, False)
        self.assertEqual(self.default_participant.deleted, True)
        self.assertEqual(ParticipantDeletionEvent.objects.count(), 0)


# FIXME: this endpoint doesn't validate the researcher on the study
# FIXME: redirect was based on referrer.
class TestResetParticipantPassword(ResearcherSessionTest):
    ENDPOINT_NAME = "participant_administration.reset_participant_password"
    REDIRECT_ENDPOINT_NAME = "participant_pages.participant_page"
    
    def test_success(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        old_password = self.default_participant.password
        self.smart_post_redirect(study_id=self.session_study.id, patient_id=self.default_participant.patient_id)
        self.default_participant.refresh_from_db()
        self.assert_present(
            "password has been reset to",
            self.easy_get("admin_pages.view_study", status_code=200, study_id=self.session_study.id).content
        )
        self.assertNotEqual(self.default_participant.password, old_password)
    
    def test_bad_participant(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        self.smart_post_redirect(study_id=self.session_study.id, patient_id="why hello")
        self.assertFalse(Participant.objects.filter(patient_id="why hello").exists())
        # self.assert_present("does not exist", self.redirect_get_contents(self.session_study.id))
        self.assert_present(
            "does not exist",
            self.easy_get(
                "admin_pages.view_study", status_code=200, study_id=self.session_study.id
            ).content
        )
    
    def test_bad_study(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        study2 = self.generate_study("study2")
        self.generate_study_relation(self.session_researcher, study2, ResearcherRole.researcher)
        old_password = self.default_participant.password
        self.smart_post_redirect(study_id=study2.id, patient_id=self.default_participant.patient_id)
        self.assert_present(
            "is not in study",
            self.easy_get("admin_pages.view_study", status_code=200, study_id=self.session_study.id).content
        )
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.password, old_password)
    
    def test_deleted_participant(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        self.default_participant.update(deleted=True)
        old_password = self.default_participant.password
        self.smart_post_redirect(study_id=self.session_study.id, patient_id=self.default_participant.patient_id)
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.password, old_password)
        page = self.redirect_get_contents(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        self.assert_present(
            PARTICIPANT_LOCKED.format(patient_id=self.default_participant.patient_id), page
        )


class TestResetDevice(ResearcherSessionTest):
    ENDPOINT_NAME = "participant_administration.reset_device"
    REDIRECT_ENDPOINT_NAME = "participant_pages.participant_page"
    
    def test_bad_study_id(self):
        self.default_participant.update(device_id="12345")
        self.set_session_study_relation(ResearcherRole.researcher)
        resp = self.smart_post(patient_id=self.default_participant.patient_id, study_id=0)
        self.assertEqual(resp.status_code, 404)
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.device_id, "12345")
    
    def test_wrong_study_id(self):
        self.default_participant.update(device_id="12345")
        self.set_session_study_relation(ResearcherRole.researcher)
        study2 = self.generate_study("study2")
        self.generate_study_relation(self.session_researcher, study2, ResearcherRole.researcher)
        self.smart_post_redirect(patient_id=self.default_participant.patient_id, study_id=study2.id)
        self.assert_present(
            "is not in study",
            self.easy_get("admin_pages.view_study", status_code=200, study_id=self.session_study.id).content
        )
        self.assertEqual(Participant.objects.count(), 1)
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.device_id, "12345")
    
    def test_bad_participant(self):
        self.default_participant.update(device_id="12345")
        self.assertEqual(Participant.objects.count(), 1)
        self.set_session_study_relation(ResearcherRole.researcher)
        self.smart_post_redirect(patient_id="invalid", study_id=self.session_study.id)
        self.assert_present(
            "does not exist",
            self.easy_get("admin_pages.view_study", status_code=200, study_id=self.session_study.id).content
        )
        
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.device_id, "12345")
    
    def test_success(self):
        self.default_participant.update(device_id="12345")
        self.set_session_study_relation(ResearcherRole.researcher)
        self.smart_post_redirect(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        self.assert_present(
            "device was reset; password is untouched",
            self.easy_get("admin_pages.view_study", status_code=200, study_id=self.session_study.id).content
        )
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.device_id, "")
    
    def test_deleted_participant(self):
        self.default_participant.update(device_id="12345", deleted=True)
        self.set_session_study_relation(ResearcherRole.researcher)
        self.smart_post_redirect(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        page = self.redirect_get_contents(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        self.assert_present(PARTICIPANT_LOCKED.format(patient_id=self.default_participant.patient_id), page)
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.device_id, "12345")


class TestToggleParticipantEasyEnrollment(ResearcherSessionTest):
    ENDPOINT_NAME = "participant_administration.toggle_easy_enrollment"
    REDIRECT_ENDPOINT_NAME = "participant_pages.participant_page"
    
    def test_admin(self):
        self.assertFalse(self.default_study.easy_enrollment)
        self.set_session_study_relation(ResearcherRole.study_admin)
        self._test_success()
    
    def test_researcher(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        self._test_success()
    
    def test_study_easy_enrollment_enabled(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        self.default_study.update(easy_enrollment=True)
        self._test_success()
    
    def _test_success(self):
        self.assertFalse(self.default_participant.easy_enrollment)
        self.smart_post_redirect(patient_id=self.default_participant.patient_id, study_id=self.session_study.id)
        self.default_participant.refresh_from_db()
        self.assertTrue(self.default_participant.easy_enrollment)
        self.smart_post_redirect(patient_id=self.default_participant.patient_id, study_id=self.session_study.id)
        self.default_participant.refresh_from_db()
        self.assertFalse(self.default_participant.easy_enrollment)
    
    def test_no_relation(self):
        self.assertFalse(self.default_participant.easy_enrollment)
        resp = self.smart_post(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        self.assertEqual(resp.status_code, 403)
        self.default_participant.refresh_from_db()
        self.assertFalse(self.default_participant.easy_enrollment)
    
    def test_deleted_participant(self):
        self.default_participant.update(deleted=True)
        self.set_session_study_relation(ResearcherRole.researcher)
        self.assertFalse(self.default_participant.easy_enrollment)
        self.smart_post_redirect(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        self.default_participant.refresh_from_db()
        self.assertFalse(self.default_participant.easy_enrollment)
        page = self.redirect_get_contents(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        self.assert_present(PARTICIPANT_LOCKED.format(patient_id=self.default_participant.patient_id), page)


class TestUnregisterParticipant(ResearcherSessionTest):
    ENDPOINT_NAME = "participant_administration.unregister_participant"
    REDIRECT_ENDPOINT_NAME = "participant_pages.participant_page"
    # most of this was copy-pasted from TestResetDevice
    
    def test_bad_study_id(self):
        self.default_participant.update(unregistered=False)
        self.set_session_study_relation(ResearcherRole.researcher)
        resp = self.smart_post(patient_id=self.default_participant.patient_id, study_id=0)
        self.assertEqual(resp.status_code, 404)
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.unregistered, False)
    
    def test_wrong_study_id(self):
        self.default_participant.update(unregistered=False)
        self.set_session_study_relation(ResearcherRole.researcher)
        study2 = self.generate_study("study2")
        self.generate_study_relation(self.session_researcher, study2, ResearcherRole.researcher)
        self.smart_post_redirect(patient_id=self.default_participant.patient_id, study_id=study2.id)
        self.assert_present(
            "is not in study",
            self.easy_get("admin_pages.view_study", status_code=200, study_id=self.session_study.id).content
        )
        self.assertEqual(Participant.objects.count(), 1)
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.unregistered, False)
    
    def test_bad_participant(self):
        self.default_participant.update(unregistered=False)
        self.assertEqual(Participant.objects.count(), 1)
        self.set_session_study_relation(ResearcherRole.researcher)
        self.smart_post_redirect(patient_id="invalid", study_id=self.session_study.id)
        self.assert_present(
            "does not exist",
            self.easy_get("admin_pages.view_study", status_code=200, study_id=self.session_study.id).content
        )
        # self.assert_present("does not exist", self.redirect_get_contents(self.session_study.id))
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.unregistered, False)
    
    def test_participant_unregistered_true(self):
        self.default_participant.update(unregistered=True)
        self.assertEqual(Participant.objects.count(), 1)
        self.set_session_study_relation(ResearcherRole.researcher)
        self.smart_post_redirect(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        self.assert_present(
            "is already unregistered",
            self.easy_get("admin_pages.view_study", status_code=200, study_id=self.session_study.id).content
        )
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.unregistered, True)
    
    def test_success(self):
        self.default_participant.update(unregistered=False)
        self.set_session_study_relation(ResearcherRole.researcher)
        self.smart_post_redirect(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        self.assert_present(
            "was successfully unregistered from the study",
            self.easy_get("admin_pages.view_study", status_code=200, study_id=self.session_study.id).content
        )
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.unregistered, True)
    
    def test_deleted_participant(self):
        self.default_participant.update(unregistered=False, deleted=True)
        self.set_session_study_relation(ResearcherRole.researcher)
        self.smart_post_redirect(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        self.default_participant.refresh_from_db()
        self.assertEqual(self.default_participant.unregistered, False)
        page = self.redirect_get_contents(
            patient_id=self.default_participant.patient_id, study_id=self.session_study.id
        )
        self.assert_present(
            PARTICIPANT_LOCKED.format(patient_id=self.default_participant.patient_id), page
        )



# FIXME: test extended database effects of generating participants
class CreateNewParticipant(ResearcherSessionTest):
    ENDPOINT_NAME = "participant_administration.create_new_participant"
    REDIRECT_ENDPOINT_NAME = "admin_pages.view_study"
    
    @patch("api.participant_administration.s3_upload")
    @patch("api.participant_administration.create_client_key_pair")
    def test(self, create_client_keypair: MagicMock, s3_upload: MagicMock):
        # this test does not make calls to S3
        self.set_session_study_relation(ResearcherRole.researcher)
        self.assertFalse(Participant.objects.exists())
        self.smart_post_redirect(study_id=self.session_study.id)
        self.assertEqual(Participant.objects.count(), 1)
        
        content = self.redirect_get_contents(self.session_study.id)
        new_participant: Participant = Participant.objects.first()
        self.assert_present("Created a new patient", content)
        self.assert_present(new_participant.patient_id, content)


class CreateManyParticipant(ResearcherSessionTest):
    ENDPOINT_NAME = "participant_administration.create_many_patients"
    
    @patch("api.participant_administration.s3_upload")
    @patch("api.participant_administration.create_client_key_pair")
    def test(self, create_client_keypair: MagicMock, s3_upload: MagicMock):
        # this test does not make calls to S3
        self.set_session_study_relation(ResearcherRole.researcher)
        self.assertFalse(Participant.objects.exists())
        
        resp: FileResponse = self.smart_post(
            self.session_study.id, desired_filename="something.csv", number_of_new_patients=10
        )
        output_file = b""
        for i, file_bytes in enumerate(resp.streaming_content, start=1):
            output_file = output_file + file_bytes
        
        self.assertEqual(i, 10)
        self.assertEqual(Participant.objects.count(), 10)
        for patient_id in Participant.objects.values_list("patient_id", flat=True):
            self.assert_present(patient_id, output_file)


#
## other_researcher_apis
#

class TestAPIGetStudies(DataApiTest):
    
    ENDPOINT_NAME = "other_researcher_apis.get_studies"
    
    def test_data_access_credential_upgrade(self):
        # check our assumptions make sense, set algorithm to sha1 and generate old-style credentials
        self.assertEqual(Researcher.DESIRED_ALGORITHM, "sha256")  # testing assumption
        self.assertEqual(Researcher.DESIRED_ITERATIONS, 1000)  # testing assumption
        self.session_researcher.DESIRED_ALGORITHM = "sha1"
        self.session_access_key, self.session_secret_key = self.session_researcher.reset_access_credentials()
        self.session_researcher.DESIRED_ALGORITHM = "sha256"
        # grab the old-style credentials, run the test_no_study test to confirm it works at all.
        original_database_value = self.session_researcher.access_key_secret
        resp = self.smart_post_status_code(200)
        self.assertEqual(Study.objects.count(), 0)
        self.assertEqual(json.loads(resp.content), {})
        # get any new credentials, make sure they're sha256
        self.session_researcher.refresh_from_db()
        self.assertNotEqual(original_database_value, self.session_researcher.access_key_secret)
        self.assertIn("sha1", original_database_value)
        self.assertIn("sha256", self.session_researcher.access_key_secret)
        # and then make sure the same password works again!
        resp = self.smart_post_status_code(200)
        self.assertEqual(Study.objects.count(), 0)
        self.assertEqual(json.loads(resp.content), {})
    
    def test_no_study(self):
        resp = self.smart_post_status_code(200)
        self.assertEqual(Study.objects.count(), 0)
        self.assertEqual(json.loads(resp.content), {})
    
    def test_no_study_relation(self):
        resp = self.smart_post_status_code(200)
        self.session_study
        self.assertEqual(Study.objects.count(), 1)
        self.assertEqual(json.loads(resp.content), {})
    
    def test_multiple_studies_one_relation(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        self.generate_study("study2")
        resp = self.smart_post_status_code(200)
        self.assertEqual(
            json.loads(resp.content), {self.session_study.object_id: self.DEFAULT_STUDY_NAME}
        )
    
    def test_study_relation(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        resp = self.smart_post_status_code(200)
        self.assertEqual(
            json.loads(resp.content), {self.session_study.object_id: self.DEFAULT_STUDY_NAME}
        )
    
    def test_multiple_studies(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        study2 = self.generate_study("study2")
        self.generate_study_relation(self.session_researcher, study2, ResearcherRole.researcher)
        resp = self.smart_post_status_code(200)
        self.assertEqual(
            json.loads(resp.content), {
                self.session_study.object_id: self.DEFAULT_STUDY_NAME,
                study2.object_id: study2.name
            }
        )


class TestApiCredentialCheck(DataApiTest):
    ENDPOINT_NAME = "other_researcher_apis.get_studies"
    
    def test_missing_all_parameters(self):
        # use _smart_post
        resp = self.less_smart_post()
        # 400, missing parameter
        self.assertEqual(400, resp.status_code)
    
    def test_only_secret_key(self):
        resp = self.less_smart_post(secret_key=self.session_secret_key)
        # 400, missing parameter
        self.assertEqual(400, resp.status_code)
    
    def test_only_access_key(self):
        resp = self.less_smart_post(access_key=self.session_access_key)
        # 400, missing parameter
        self.assertEqual(400, resp.status_code)
    
    def test_regex_validation(self):
        # Weird, but keep it, useful when debugging this test.
        self.session_researcher.access_key_secret = "apples"
        self.assertRaises(ValidationError, self.session_researcher.save)
    
    def test_wrong_secret_key_db(self):
        # Weird, but keep it, useful when debugging this test.
        the_id = self.session_researcher.id  # instantiate the researcher, get their id
        # have to bypass validation
        Researcher.objects.filter(id=the_id).update(access_key_secret="apples")
        resp = self.smart_post()
        # key doesn't match, forbidden
        self.assertEqual(403, resp.status_code)
    
    def test_wrong_secret_key_post(self):
        resp = self.less_smart_post(access_key="apples", secret_key=self.session_secret_key)
        # key doesn't match, forbidden
        self.assertEqual(403, resp.status_code)
    
    def test_wrong_access_key_db(self):
        # Weird, but keep it, useful when debugging this test.
        self.session_researcher.access_key_id = "apples"
        self.session_researcher.save()
        resp = self.smart_post()
        # no such user, forbidden
        self.assertEqual(403, resp.status_code)
    
    def test_wrong_access_key_post(self):
        resp = self.less_smart_post(access_key=self.session_access_key, secret_key="apples")
        # no such user, forbidden
        self.assertEqual(403, resp.status_code)
    
    def test_access_key_special_characters(self):
        self.session_access_key = "\x00" * 64
        self.smart_post_status_code(400)
    
    def test_secret_key_special_characters(self):
        self.session_secret_key = "\x00" * 64
        self.smart_post_status_code(400)
    
    def test_site_admin(self):
        self.assign_role(self.session_researcher, ResearcherRole.site_admin)
        self.smart_post_status_code(200)
    
    def test_researcher(self):
        self.assign_role(self.session_researcher, ResearcherRole.study_admin)
        self.smart_post_status_code(200)
    
    def test_study_admin(self):
        self.assign_role(self.session_researcher, ResearcherRole.researcher)
        self.smart_post_status_code(200)


class TestAPIStudyUserAccess(DataApiTest):
    ENDPOINT_NAME = "other_researcher_apis.get_users_in_study"
    
    def test_missing_all_parameters(self):
        # self.set_session_study_relation(ResearcherRole)
        # use _smart_post
        resp = self.less_smart_post()
        # 400, missing parameter
        self.assertEqual(400, resp.status_code)
    
    def test_only_secret_key(self):
        resp = self.less_smart_post(secret_key=self.session_secret_key)
        # 400, missing parameter
        self.assertEqual(400, resp.status_code)
    
    def test_only_access_key(self):
        resp = self.less_smart_post(access_key=self.session_access_key)
        # 400, missing parameter
        self.assertEqual(400, resp.status_code)
    
    def test_only_study_obj_id(self):
        resp = self.less_smart_post(study_id=self.session_study.object_id)
        # 400, missing parameter
        self.assertEqual(400, resp.status_code)
    
    def test_only_study_pk(self):
        resp = self.less_smart_post(study_pk=self.session_study.pk)
        # 400, missing parameter
        self.assertEqual(400, resp.status_code)
    
    def test_wrong_secret_key_post(self):
        resp = self.less_smart_post(
            access_key="apples", secret_key=self.session_secret_key, study_pk=self.session_study.pk
        )
        # key doesn't match, forbidden
        self.assertEqual(403, resp.status_code)
    
    def test_wrong_access_key_post(self):
        resp = self.less_smart_post(
            access_key=self.session_access_key, secret_key="apples", study_pk=self.session_study.pk
        )
        # no such user, forbidden
        self.assertEqual(403, resp.status_code)
    
    def test_no_such_study_pk(self):
        # 0 is an invalid study id
        self.smart_post_status_code(404, study_pk=0)
    
    def test_no_such_study_obj(self):
        # 0 is an invalid study id
        self.smart_post_status_code(404, study_id='a'*24)
    
    def test_bad_object_id(self):
        # 0 is an invalid study id
        self.smart_post_status_code(400, study_id='['*24)
        self.smart_post_status_code(400, study_id='a'*5)
    
    def test_access_key_special_characters(self):
        self.session_access_key = "\x00" * 64
        self.smart_post_status_code(400, study_pk=self.session_study.pk)
    
    def test_secret_key_special_characters(self):
        self.session_secret_key = "\x00" * 64
        self.smart_post_status_code(400, study_pk=self.session_study.pk)
    
    def test_site_admin(self):
        self.assign_role(self.session_researcher, ResearcherRole.site_admin)
        self.smart_post_status_code(200, study_pk=self.session_study.pk)
    
    def test_researcher(self):
        self.assign_role(self.session_researcher, ResearcherRole.study_admin)
        self.smart_post_status_code(200, study_pk=self.session_study.pk)
    
    def test_study_admin(self):
        self.assign_role(self.session_researcher, ResearcherRole.researcher)
        self.smart_post_status_code(200, study_pk=self.session_study.pk)
    
    def test_no_relation(self):
        self.assign_role(self.session_researcher, None)
        self.smart_post_status_code(403, study_pk=self.session_study.pk)


class TestGetUsersInStudy(DataApiTest):
    ENDPOINT_NAME = "other_researcher_apis.get_users_in_study"
    
    def test_no_participants(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        resp = self.smart_post_status_code(200, study_id=self.session_study.object_id)
        self.assertEqual(resp.content, b"[]")
    
    def test_one_participant(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        self.default_participant
        resp = self.smart_post_status_code(200, study_id=self.session_study.object_id)
        self.assertEqual(resp.content, f'["{self.default_participant.patient_id}"]'.encode())
    
    def test_two_participants(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        self.default_participant
        p2 = self.generate_participant(self.session_study)
        resp = self.smart_post_status_code(200, study_id=self.session_study.object_id)
        # ordering here is random because generate_participant is random, so we will just test both.
        match = f'["{self.default_participant.patient_id}", "{p2.patient_id}"]'
        match2 = f'["{p2.patient_id}", "{self.default_participant.patient_id}"]'
        try:
            self.assertEqual(resp.content, match.encode())
        except AssertionError:
            self.assertEqual(resp.content, match2.encode())


class TestDownloadStudyInterventions(DataApiTest):
    ENDPOINT_NAME = "other_researcher_apis.download_study_interventions"
    
    def test_no_interventions(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        resp = self.smart_post_status_code(200, study_id=self.session_study.object_id)
        self.assertEqual(resp.content, b"{}")
    
    def test_survey_with_one_intervention(self):
        self.set_session_study_relation(ResearcherRole.researcher)
        self.default_populated_intervention_date
        self.default_relative_schedule
        resp = self.smart_post_status_code(200, study_id=self.session_study.object_id)
        json_unpacked = json.loads(resp.content)
        correct_output = {self.DEFAULT_PARTICIPANT_NAME:
                            {self.DEFAULT_SURVEY_OBJECT_ID:
                                {self.DEFAULT_INTERVENTION_NAME: self.CURRENT_DATE.isoformat()}}}
        self.assertDictEqual(json_unpacked, correct_output)


#
## data_access_api
#

class TestGetData(DataApiTest):
    """ WARNING: there are heisenbugs in debugging the download data api endpoint.

    There is a generator that is conditionally present (`handle_database_query`), it can swallow
    errors. As a generater iterating over it consumes it, so printing it breaks the code.
    
    You Must Patch libs.streaming_zip.ThreadPool
        The database connection breaks throwing errors on queries that should succeed.
        The iterator inside the zip file generator generally fails, and the zip file is empty.

    You Must Patch libs.streaming_zip.s3_retrieve
        Otherwise s3_retrieve will fail due to the patch is tests.common.
    """
    
    def test_s3_patch_present(self):
        from libs import s3
        self.assertIs(s3.S3_BUCKET, Exception)
    
    ENDPOINT_NAME = "data_access_api.get_data"
    
    EMPTY_ZIP = b'PK\x05\x06\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
    SIMPLE_FILE_CONTENTS = b"this is the file content you are looking for"
    REGISTRY_HASH = "registry_hash"
    
    # retain and usethis structure in order to force a test addition on a new file type.
    # "particip" is the DEFAULT_PARTICIPANT_NAME
    # 'u1Z3SH7l2xNsw72hN3LnYi96' is the  DEFAULT_SURVEY_OBJECT_ID
    PATIENT_NAME = CommonTestCase.DEFAULT_PARTICIPANT_NAME
    FILE_NAMES = {                                        # ↓ that Z makes it a timzone'd datetime
        "accelerometer": ("something.csv", "2020-10-05 02:00Z",
                         f"{PATIENT_NAME}/accelerometer/2020-10-05 02_00_00+00_00.csv"),
        "ambient_audio": ("something.mp4", "2020-10-05 02:00Z",
                         f"{PATIENT_NAME}/ambient_audio/2020-10-05 02_00_00+00_00.mp4"),
        "app_log": ("app_log.csv", "2020-10-05 02:00Z",
                         f"{PATIENT_NAME}/app_log/2020-10-05 02_00_00+00_00.csv"),
        "bluetooth": ("bluetooth.csv", "2020-10-05 02:00Z",
                         f"{PATIENT_NAME}/bluetooth/2020-10-05 02_00_00+00_00.csv"),
        "calls": ("calls.csv", "2020-10-05 02:00Z",
                         f"{PATIENT_NAME}/calls/2020-10-05 02_00_00+00_00.csv"),
        "devicemotion": ("devicemotion.csv", "2020-10-05 02:00Z",
                         f"{PATIENT_NAME}/devicemotion/2020-10-05 02_00_00+00_00.csv"),
        "gps": ("gps.csv", "2020-10-05 02:00Z",
                         f"{PATIENT_NAME}/gps/2020-10-05 02_00_00+00_00.csv"),
        "gyro": ("gyro.csv", "2020-10-05 02:00Z",
                         f"{PATIENT_NAME}/gyro/2020-10-05 02_00_00+00_00.csv"),
        "identifiers": ("identifiers.csv", "2020-10-05 02:00Z",
                         f"{PATIENT_NAME}/identifiers/2020-10-05 02_00_00+00_00.csv"),
        "image_survey": ("image_survey/survey_obj_id/something/something2.csv", "2020-10-05 02:00Z",
                         # patient_id/data_type/survey_id/survey_instance/name.csv
                         f"{PATIENT_NAME}/image_survey/survey_obj_id/something/something2.csv"),
        "ios_log": ("ios_log.csv", "2020-10-05 02:00Z",
                         f"{PATIENT_NAME}/ios_log/2020-10-05 02_00_00+00_00.csv"),
        "magnetometer": ("magnetometer.csv", "2020-10-05 02:00Z",
                         f"{PATIENT_NAME}/magnetometer/2020-10-05 02_00_00+00_00.csv"),
        "power_state": ("power_state.csv", "2020-10-05 02:00Z",
                         f"{PATIENT_NAME}/power_state/2020-10-05 02_00_00+00_00.csv"),
        "proximity": ("proximity.csv", "2020-10-05 02:00Z",
                         f"{PATIENT_NAME}/proximity/2020-10-05 02_00_00+00_00.csv"),
        "reachability": ("reachability.csv", "2020-10-05 02:00Z",
                         f"{PATIENT_NAME}/reachability/2020-10-05 02_00_00+00_00.csv"),
        "survey_answers": ("survey_obj_id/something2/something3.csv", "2020-10-05 02:00Z",
                          # expecting: patient_id/data_type/survey_id/time.csv
                         f"{PATIENT_NAME}/survey_answers/something2/2020-10-05 02_00_00+00_00.csv"),
        "survey_timings": ("something1/something2/something3/something4/something5.csv", "2020-10-05 02:00Z",
                          # expecting: patient_id/data_type/survey_id/time.csv
                          f"{PATIENT_NAME}/survey_timings/u1Z3SH7l2xNsw72hN3LnYi96/2020-10-05 02_00_00+00_00.csv"),
        "texts": ("texts.csv", "2020-10-05 02:00Z",
                         f"{PATIENT_NAME}/texts/2020-10-05 02_00_00+00_00.csv"),
        "audio_recordings": ("audio_recordings.wav", "2020-10-05 02:00Z",
                         f"{PATIENT_NAME}/audio_recordings/2020-10-05 02_00_00+00_00.wav"),
        "wifi": ("wifi.csv", "2020-10-05 02:00Z",
                         f"{PATIENT_NAME}/wifi/2020-10-05 02_00_00+00_00.csv"),
        }
    
    # setting the threadpool needs to apply to each test, following this pattern because its easy.
    @patch("libs.streaming_zip.ThreadPool")
    def test_basics(self, threadpool: MagicMock):
        threadpool.return_value = DummyThreadPool()
        self._test_basics(as_site_admin=False)
    
    @patch("libs.streaming_zip.ThreadPool")
    def test_basics_as_site_admin(self, threadpool: MagicMock):
        threadpool.return_value = DummyThreadPool()
        self._test_basics(as_site_admin=True)
    
    @patch("libs.streaming_zip.ThreadPool")
    def test_downloads_and_file_naming(self, threadpool: MagicMock):
        threadpool.return_value = DummyThreadPool()
        self._test_downloads_and_file_naming()
    
    @patch("libs.streaming_zip.ThreadPool")
    def test_registry_doesnt_download(self, threadpool: MagicMock):
        threadpool.return_value = DummyThreadPool()
        self._test_registry_doesnt_download()
    
    @patch("libs.streaming_zip.ThreadPool")
    def test_time_bin(self, threadpool: MagicMock):
        threadpool.return_value = DummyThreadPool()
        self._test_time_bin()
    
    @patch("libs.streaming_zip.ThreadPool")
    def test_user_query(self, threadpool: MagicMock):
        threadpool.return_value = DummyThreadPool()
        self._test_user_query()
    
    @patch("libs.streaming_zip.ThreadPool")
    def test_data_streams(self, threadpool: MagicMock):
        threadpool.return_value = DummyThreadPool()
        self._test_data_streams()
    
    # but don't patch ThreadPool for this one
    def test_downloads_and_file_naming_heisenbug(self):
        # As far as I can tell the ThreadPool seems to screw up the connection to the test
        # database, and queries on the non-main thread either find no data or connect to the wrong
        # database (presumably your normal database?).
        # Please retain this behavior and consult me (Eli, Biblicabeebli) during review.  This means a
        # change has occurred to the multithreading, and is probably related to an obscure but known
        # memory leak in the data access api download enpoint that is relevant on large downloads. """
        try:
            self._test_downloads_and_file_naming()
        except AssertionError as e:
            # this will happen on the first file it tests, accelerometer.
            literal_string_of_error_message = f"b'{self.PATIENT_NAME}/accelerometer/2020-10-05 " \
                "02_00_00+00_00.csv' not found in b'PK\\x05\\x06\\x00\\x00\\x00\\x00\\x00" \
                "\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00\\x00'"
            
            if str(e) != literal_string_of_error_message:
                raise Exception(
                    f"\n'{literal_string_of_error_message}'\nwas not equal to\n'{str(e)}'\n"
                    "\n  You have changed something that is possibly related to "
                    "threading via a ThreadPool or DummyThreadPool"
                )
    
    def _test_basics(self, as_site_admin: bool):
        if as_site_admin:
            self.session_researcher.update(site_admin=True)
        else:
            self.set_session_study_relation(ResearcherRole.researcher)
        resp: FileResponse = self.smart_post(study_pk=self.session_study.id, web_form="anything")
        self.assertEqual(resp.status_code, 200)
        for i, file_bytes in enumerate(resp.streaming_content, start=1):
            pass
        self.assertEqual(i, 1)
        # this is an empty zip file as output by the api.  PK\x05\x06 is zip-speak for an empty
        # container.  Behavior can vary on how zip decompressors handle an empty zip, some fail.
        self.assertEqual(file_bytes, self.EMPTY_ZIP)
        
        # test without web_form, which will create the registry file (which is empty)
        resp2: FileResponse = self.smart_post(study_pk=self.session_study.id)
        self.assertEqual(resp2.status_code, 200)
        file_content = b""
        for i2, file_bytes2 in enumerate(resp2.streaming_content, start=1):
            file_content = file_content + file_bytes2
        self.assertEqual(i2, 2)
        self.assert_present(b"registry{}", file_content)
    
    @patch("libs.streaming_zip.s3_retrieve")
    def _test_downloads_and_file_naming(self, s3_retrieve: MagicMock):
        # basics
        s3_retrieve.return_value = self.SIMPLE_FILE_CONTENTS
        self.set_session_study_relation(ResearcherRole.researcher)
        
        # need to test all data types
        for data_type in ALL_DATA_STREAMS:
            path, time_bin, output_name = self.FILE_NAMES[data_type]
            file_contents = self.generate_chunkregistry_and_download(data_type, path, time_bin)
            # this is an 'in' test because the file name is part of the zip file, as cleartext
            self.assertIn(output_name.encode(), file_contents)
            self.assertIn(s3_retrieve.return_value, file_contents)
    
    @patch("libs.streaming_zip.s3_retrieve")
    def _test_data_streams(self, s3_retrieve: MagicMock):
        # basics
        s3_retrieve.return_value = self.SIMPLE_FILE_CONTENTS
        self.set_session_study_relation(ResearcherRole.researcher)
        file_path = "some_file_path.csv"
        basic_args = ("accelerometer", file_path, "2020-10-05 02:00Z")
        
        # assert normal args actually work
        file_contents = self.generate_chunkregistry_and_download(*basic_args)
        self.assertNotEqual(file_contents, self.EMPTY_ZIP)
        
        # test matching data type downloads
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args, query_data_streams='["accelerometer"]'
        )
        self.assertNotEqual(file_contents, self.EMPTY_ZIP)
        # same with only the string (no brackets, client.post handles serialization)
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args, query_data_streams="accelerometer"
        )
        self.assertNotEqual(file_contents, self.EMPTY_ZIP)
        
        # test invalid data stream
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args, query_data_streams='"[accelerometer,gyro]', status_code=404
        )
        
        # test valid, non-matching data type does not download
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args, query_data_streams='["gyro"]'
        )
        self.assertEqual(file_contents, self.EMPTY_ZIP)
    
    @patch("libs.streaming_zip.s3_retrieve")
    def _test_registry_doesnt_download(self, s3_retrieve: MagicMock):
        # basics
        s3_retrieve.return_value = self.SIMPLE_FILE_CONTENTS
        self.set_session_study_relation(ResearcherRole.researcher)
        file_path = "some_file_path.csv"
        basic_args = ("accelerometer", file_path, "2020-10-05 02:00Z")
        
        # assert normal args actually work
        file_contents = self.generate_chunkregistry_and_download(*basic_args)
        self.assertNotEqual(file_contents, self.EMPTY_ZIP)
        
        # test that file is not downloaded when a valid json registry is present
        # (the test for the empty zip is much, easiest, even if this combination of parameters
        # is technically not kosher.)
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args, registry=json.dumps({file_path: self.REGISTRY_HASH}), force_web_form=True
        )
        self.assertEqual(file_contents, self.EMPTY_ZIP)
        
        # test that a non-matching hash does not block download.
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args, registry=json.dumps({file_path: "bad hash value"})
        )
        self.assertNotEqual(file_contents, self.EMPTY_ZIP)
        
        # test bad json objects
        self.generate_chunkregistry_and_download(
            *basic_args, registry=json.dumps([self.REGISTRY_HASH]), status_code=400
        )
        self.generate_chunkregistry_and_download(
            *basic_args, registry=json.dumps([file_path]), status_code=400
        )
        # empty string is probably worth testing
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args, registry="", status_code=400
        )
    
    @patch("libs.streaming_zip.s3_retrieve")
    def _test_time_bin(self, s3_retrieve: MagicMock):
        # basics
        s3_retrieve.return_value = self.SIMPLE_FILE_CONTENTS
        self.set_session_study_relation(ResearcherRole.researcher)
        basic_args = ("accelerometer", "some_file_path.csv", "2020-10-05 02:00Z")
        
        # generic request should succeed
        file_contents = self.generate_chunkregistry_and_download(*basic_args)
        self.assertNotEqual(file_contents, self.EMPTY_ZIP)
        self.assertIn(self.SIMPLE_FILE_CONTENTS, file_contents)
        
        # the api time parameter format is "%Y-%m-%dT%H:%M:%S"
        # from a time before time_bin of chunkregistry
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args, query_time_bin_start="2020-10-05T01:00:00",
        )
        self.assertNotEqual(file_contents, self.EMPTY_ZIP)
        self.assertIn(self.SIMPLE_FILE_CONTENTS, file_contents)
        
        # inner check should be equal to or after the given date
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args, query_time_bin_start="2020-10-05T02:00:00",
        )
        self.assertNotEqual(file_contents, self.EMPTY_ZIP)
        self.assertIn(self.SIMPLE_FILE_CONTENTS, file_contents)
        
        # inner check should be equal to or before the given date
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args, query_time_bin_end="2020-10-05T02:00:00",
        )
        self.assertNotEqual(file_contents, self.EMPTY_ZIP)
        self.assertIn(self.SIMPLE_FILE_CONTENTS, file_contents)
        
        # this should fail, start date is late
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args, query_time_bin_start="2020-10-05T03:00:00",
        )
        self.assertEqual(file_contents, self.EMPTY_ZIP)
        
        # this should succeed, end date is after start date
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args, query_time_bin_end="2020-10-05T03:00:00",
        )
        self.assertNotEqual(file_contents, self.EMPTY_ZIP)
        self.assertIn(self.SIMPLE_FILE_CONTENTS, file_contents)
        
        # should succeed, within time range
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args,
            query_time_bin_start="2020-10-05T02:00:00",
            query_time_bin_end="2020-10-05T03:00:00",
        )
        self.assertNotEqual(file_contents, self.EMPTY_ZIP)
        self.assertIn(self.SIMPLE_FILE_CONTENTS, file_contents)
        
        # test with bad time bins, returns no data, user error, no special case handling
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args,
            query_time_bin_start="2020-10-05T03:00:00",
            query_time_bin_end="2020-10-05T02:00:00",
        )
        self.assertEqual(file_contents, self.EMPTY_ZIP)
        
        # test inclusive
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args,
            query_time_bin_start="2020-10-05T02:00:00",
            query_time_bin_end="2020-10-05T02:00:00",
        )
        self.assertNotEqual(file_contents, self.EMPTY_ZIP)
        self.assertIn(self.SIMPLE_FILE_CONTENTS, file_contents)
        
        # test bad time format
        self.generate_chunkregistry_and_download(
            *basic_args, query_time_bin_start="2020-10-05 01:00:00", status_code=400
        )
    
    @patch("libs.streaming_zip.s3_retrieve")
    def _test_user_query(self, s3_retrieve: MagicMock):
        # basics
        s3_retrieve.return_value = self.SIMPLE_FILE_CONTENTS
        self.set_session_study_relation(ResearcherRole.researcher)
        basic_args = ("accelerometer", "some_file_path.csv", "2020-10-05 02:00Z")
        
        # generic request should succeed
        file_contents = self.generate_chunkregistry_and_download(*basic_args)
        self.assertNotEqual(file_contents, self.EMPTY_ZIP)
        self.assertIn(self.SIMPLE_FILE_CONTENTS, file_contents)
        
        # Test bad username
        output_status_code = self.generate_chunkregistry_and_download(
            *basic_args, query_patient_ids='["jeff"]', status_code=404
        )
        self.assertEqual(output_status_code, 404)  # redundant, whatever
        
        # test working participant filter
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args, query_patient_ids=[self.default_participant.patient_id],
        )
        self.assertNotEqual(file_contents, self.EMPTY_ZIP)
        self.assertIn(self.SIMPLE_FILE_CONTENTS, file_contents)
        # same but just the string
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args, query_patient_ids=self.default_participant.patient_id,
        )
        self.assertNotEqual(file_contents, self.EMPTY_ZIP)
        self.assertIn(self.SIMPLE_FILE_CONTENTS, file_contents)
        
        # test empty patients doesn't do anything
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args, query_patient_ids='[]',
        )
        self.assertNotEqual(file_contents, self.EMPTY_ZIP)
        self.assertIn(self.SIMPLE_FILE_CONTENTS, file_contents)
        
        # test no matching data. create user, query for that user
        self.generate_participant(self.session_study, "jeff")
        file_contents = self.generate_chunkregistry_and_download(
            *basic_args, query_patient_ids='["jeff"]',
        )
        self.assertEqual(file_contents, self.EMPTY_ZIP)
    
    def generate_chunkregistry_and_download(
        self,
        data_type: str,
        file_path: str,
        time_bin: str,
        status_code: int = 200,
        registry: bool = None,
        query_time_bin_start: str = None,
        query_time_bin_end: str = None,
        query_patient_ids: str = None,
        query_data_streams: str = None,
        force_web_form: bool = False,
    ):
        post_kwargs = {"study_pk": self.session_study.id}
        generate_kwargs = {"time_bin": time_bin, "path": file_path}
        tracking = {"researcher": self.session_researcher, "query_params": {}}
        
        if data_type == SURVEY_TIMINGS:
            generate_kwargs["survey"] = self.default_survey
        
        if registry is not None:
            post_kwargs["registry"] = registry
            generate_kwargs["hash_value"] = self.REGISTRY_HASH  # strings must match
            tracking["registry_dict_size"] = True
        else:
            post_kwargs["web_form"] = ""
        
        if force_web_form:
            post_kwargs["web_form"] = ""
        
        if query_data_streams is not None:
            post_kwargs["data_streams"] = query_data_streams
            tracking["query_params"]["data_streams"] = query_data_streams
        
        if query_patient_ids is not None:
            post_kwargs["user_ids"] = query_patient_ids
            tracking["user_ids"] = query_patient_ids
        
        if query_time_bin_start:
            post_kwargs['time_start'] = query_time_bin_start
            tracking['time_start'] = query_time_bin_start
        if query_time_bin_end:
            post_kwargs['time_end'] = query_time_bin_end
            tracking['time_end'] = query_time_bin_end
        
        # clear records, create chunkregistry and post
        DataAccessRecord.objects.all().delete()  # we automate tihs testing, easiest to clear it
        self.generate_chunkregistry(
            self.session_study, self.default_participant, data_type, **generate_kwargs
        )
        resp: FileResponse = self.smart_post(**post_kwargs)
        
        # some basics for testing that DataAccessRecords are created
        assert DataAccessRecord.objects.count() == 1, (post_kwargs, resp.status_code, DataAccessRecord.objects.count())
        record = DataAccessRecord.objects.order_by("-created_on").first()
        self.assertEqual(record.researcher.id, self.session_researcher.id)
        
        # Test for a status code, default 200
        self.assertEqual(resp.status_code, status_code)
        if resp.status_code != 200:
            # no iteration, clear db
            ChunkRegistry.objects.all().delete()
            return resp.status_code
        
        # directly comparing these dictionaries is quite non-trivial, not really worth testing tbh?
        # post_kwargs.pop("web_form")
        # self.assertEqual(json.loads(record.query_params), post_kwargs)
        
        # then iterate over the streaming output and concatenate it.
        bytes_list = []
        for i, file_bytes in enumerate(resp.streaming_content, start=1):
            bytes_list.append(file_bytes)
            # print(data_type, i, file_bytes)
        
        # database cleanup has to be after the iteration over the file contents
        ChunkRegistry.objects.all().delete()
        return b"".join(bytes_list)


#
## mobile_api
#

class TestParticipantSetPassword(ParticipantSessionTest):
    ENDPOINT_NAME = "mobile_api.set_password"
    
    def test_no_paramaters(self):
        self.smart_post_status_code(400)
        self.session_participant.refresh_from_db()
        self.assertFalse(self.session_participant.validate_password(self.DEFAULT_PARTICIPANT_PASSWORD))
        self.assertTrue(self.session_participant.debug_validate_password(self.DEFAULT_PARTICIPANT_PASSWORD))
    
    def test_correct_paramater(self):
        self.assertIsNone(self.default_participant.last_set_password)
        self.smart_post_status_code(200, new_password="jeff")
        self.session_participant.refresh_from_db()
        # participant passwords are weird there's some hashing
        self.assertFalse(self.session_participant.validate_password("jeff"))
        self.assertTrue(self.session_participant.debug_validate_password("jeff"))
        # test last_set_password_is_set
        self.assertIsInstance(self.default_participant.last_set_password, datetime)
    
    def test_deleted_participant(self):
        self.INJECT_DEVICE_TRACKER_PARAMS = False
        self.default_participant.update(deleted=True)
        response = self.smart_post_status_code(403)
        self.assertEqual(response.content, b"")
        self.INJECT_DEVICE_TRACKER_PARAMS = True


class TestGetLatestSurveys(ParticipantSessionTest):
    ENDPOINT_NAME = "mobile_api.get_latest_surveys"
    
    @property
    def BASIC_SURVEY_CONTENT(self):
        return [
            {
                '_id': self.DEFAULT_SURVEY_OBJECT_ID,
                'content': [],
                'settings': {},
                'survey_type': 'tracking_survey',
                'timings': EMPTY_WEEKLY_SURVEY_TIMINGS(),
                'name': "",
            }
        ]
    
    def test_no_surveys(self):
        resp = self.smart_post_status_code(200)
        self.assertEqual(resp.content, b"[]")
    
    def test_basic_survey(self):
        self.assertIsNone(self.default_participant.last_get_latest_surveys)
        self.default_survey
        resp = self.smart_post_status_code(200)
        output_survey = json.loads(resp.content.decode())
        self.assertEqual(output_survey, self.BASIC_SURVEY_CONTENT)
        # test last_get_latest_surveys is set
        self.session_participant.refresh_from_db()
        self.assertIsInstance(self.default_participant.last_get_latest_surveys, datetime)
    
    def test_weekly_basics(self):
        self.default_survey
        resp = self.smart_post_status_code(200)
        output_survey = json.loads(resp.content.decode())
        reference_output = self.BASIC_SURVEY_CONTENT
        reference_output[0]["timings"] = MIDNIGHT_EVERY_DAY()
        WeeklySchedule.create_weekly_schedules(MIDNIGHT_EVERY_DAY(), self.default_survey)
        self.assertEqual(output_survey, self.BASIC_SURVEY_CONTENT)
    
    def test_weekly_basics2(self):
        self.default_survey
        reference_output = self.BASIC_SURVEY_CONTENT
        reference_output[0]["timings"] = MIDNIGHT_EVERY_DAY()
        WeeklySchedule.create_weekly_schedules(MIDNIGHT_EVERY_DAY(), self.default_survey)
        resp = self.smart_post_status_code(200)
        output_survey = json.loads(resp.content.decode())
        self.assertEqual(output_survey, reference_output)
    
    @time_machine.travel(THURS_OCT_6_NOON_2022_NY)
    def test_absolute_schedule_basics(self):
        # test for absolute surveys that they show up regardless of the day of the week they fall on,
        # as long as that day is within the current week.
        self.default_survey
        for day_of_week_index in self.iterate_weekday_absolute_schedules():
            resp = self.smart_post_status_code(200)
            api_survey_representation = json.loads(resp.content.decode())
            reference_representation = self.BASIC_SURVEY_CONTENT
            reference_representation[0]["timings"][day_of_week_index] = [0]
            self.assertEqual(api_survey_representation, reference_representation)
    
    def iterate_weekday_absolute_schedules(self):
        # iterates over days of the week and populates absolute schedules and scheduled events
        start, _ = get_start_and_end_of_java_timings_week(timezone.now())
        for i in range(0, 7):
            AbsoluteSchedule.objects.all().delete()
            ScheduledEvent.objects.all().delete()
            a_date = start.date() + timedelta(days=i)
            self.generate_absolute_schedule(a_date)
            repopulate_absolute_survey_schedule_events(self.default_survey, self.default_participant)
            # correct weekday for sunday-zero-index
            yield (a_date.weekday() + 1) % 7
    
    # absolutes
    def test_absolute_schedule_out_of_range_future(self):
        self.default_survey
        self.generate_absolute_schedule(date.today() + timedelta(days=200))
        repopulate_absolute_survey_schedule_events(self.default_survey, self.default_participant)
        resp = self.smart_post_status_code(200)
        output_survey = json.loads(resp.content.decode())
        self.assertEqual(output_survey, self.BASIC_SURVEY_CONTENT)
    
    def test_absolute_schedule_out_of_range_past(self):
        self.default_survey
        self.generate_absolute_schedule(date.today() - timedelta(days=200))
        repopulate_absolute_survey_schedule_events(self.default_survey, self.default_participant)
        resp = self.smart_post_status_code(200)
        output_survey = json.loads(resp.content.decode())
        self.assertEqual(output_survey, self.BASIC_SURVEY_CONTENT)
    
    @time_machine.travel(THURS_OCT_6_NOON_2022_NY)
    def test_relative_schedule_basics(self):
        # this test needds to run on a thursday
        # test that a relative survey creates schedules that get output in survey timings at all
        self.generate_relative_schedule(self.default_survey, self.default_intervention, days_after=-1)
        self.default_populated_intervention_date.date
        repopulate_relative_survey_schedule_events(self.default_survey, self.default_participant)
        resp = self.smart_post_status_code(200)
        output_survey = json.loads(resp.content.decode())
        output_basic = self.BASIC_SURVEY_CONTENT
        timings_out = output_survey[0].pop("timings")
        timings_basic = output_basic[0].pop("timings")
        self.assertEqual(output_survey, output_basic)  # assert only the timings have changed
        self.assertNotEqual(timings_out, timings_basic)
        timings_basic[3].append(0)
        self.assertEqual(timings_out, timings_basic)
    
    def test_relative_schedule_out_of_range_future(self):
        self.generate_relative_schedule(self.default_survey, self.default_intervention, days_after=200)
        self.default_populated_intervention_date
        repopulate_relative_survey_schedule_events(self.default_survey, self.default_participant)
        resp = self.smart_post_status_code(200)
        output_survey = json.loads(resp.content.decode())
        self.assertEqual(output_survey, self.BASIC_SURVEY_CONTENT)
    
    def test_relative_schedule_out_of_range_past(self):
        self.generate_relative_schedule(self.default_survey, self.default_intervention, days_after=-200)
        self.default_populated_intervention_date
        repopulate_relative_survey_schedule_events(self.default_survey, self.default_participant)
        resp = self.smart_post_status_code(200)
        output_survey = json.loads(resp.content.decode())
        self.assertEqual(output_survey, self.BASIC_SURVEY_CONTENT)
    
    # todo: work out how to iterate over variant relative schedules because that is obnoxious.
    # def test_something_relative(self):
    #     start, end = get_start_and_end_of_java_timings_week(timezone.now())
    
    #     for day in date_list(start, timedelta(days=1), 7):
    #         for self.iterate_days_relative_schedules(start, end, )
    
    def iterate_days_relative_schedules(self, days_before, days_after, date_of_intervention: date):
        # generates one relative schedule per day for the range given.
        # generates an intervention, and (possibly?) scheduled event for the schedule.
        # generates an intervention date on the default participant intervention date
        intervention = self.generate_intervention(self.default_study, "an intervention")
        self.generate_intervention_date(self.default_participant, intervention, date_of_intervention)
        rel_sched = self.generate_relative_schedule(self.default_survey, intervention, days_after=days_after)
        
        for days_relative in range(days_before * -1, days_after):
            rel_sched.update(days_after=days_relative)
            repopulate_absolute_survey_schedule_events(self.default_survey, self.default_participant)
            yield days_relative
    
    def test_deleted_participant(self):
        self.INJECT_DEVICE_TRACKER_PARAMS = False
        self.default_participant.update(deleted=True)
        response = self.smart_post_status_code(403)
        self.assertEqual(response.content, b"")
        self.INJECT_DEVICE_TRACKER_PARAMS = True


class TestRegisterParticipant(ParticipantSessionTest):
    ENDPOINT_NAME = "mobile_api.register_user"
    DISABLE_CREDENTIALS = True
    NEW_PASSWORD = "something_new"
    NEW_PASSWORD_HASHED = device_hash(NEW_PASSWORD.encode()).decode()
    
    @property
    def BASIC_PARAMS(self):
        return {
            'patient_id': self.session_participant.patient_id,
            'phone_number': "0000000000",
            'device_id': "pretty_much anything",
            'device_os': "something",
            'os_version': "something",
            "product": "something",
            "brand": "something",
            "hardware_id": "something",
            "manufacturer": "something",
            "model": "something",
            "beiwe_version": "something",
            "new_password": self.NEW_PASSWORD,
            "password": self.DEFAULT_PARTICIPANT_PASSWORD_HASHED
        }
    
    def test_bad_request(self):
        self.skip_next_device_tracker_params
        self.smart_post_status_code(403)
    
    @patch("api.mobile_api.s3_upload")
    @patch("api.mobile_api.get_client_public_key_string")
    def test_success_unregistered_before(
        self, get_client_public_key_string: MagicMock, s3_upload: MagicMock
    ):
        # This test has no intervention dates, a case doesn't ~really exist anymore because loading
        # the participant page will populate the value on all participants if it is missing, with a
        # date value of None. The followup test includes a participant with a None intervention so
        # its probably fine.
        s3_upload.return_value = None
        self.assertIsNone(self.default_participant.last_register_user)
        get_client_public_key_string.return_value = "a_private_key"
        # unregistered participants have no device id
        self.session_participant.update(device_id="")
        resp = self.smart_post_status_code(200, **self.BASIC_PARAMS)
        
        response_dict = json.loads(resp.content)
        self.assertEqual("a_private_key", response_dict["client_public_key"])
        self.session_participant.refresh_from_db()
        self.assertTrue(self.session_participant.validate_password(self.NEW_PASSWORD_HASHED))
        self.assertIsInstance(self.default_participant.last_register_user, datetime)
    
    @patch("api.mobile_api.s3_upload")
    @patch("api.mobile_api.get_client_public_key_string")
    def test_success_unregistered_complex_study(
        self, get_client_public_key_string: MagicMock, s3_upload: MagicMock
    ):
        # there was a bug where participants with intervention dates set equal to None would crash
        # inside repopulate_relative_survey_schedule_events because they were not being filtered out,
        # but the bug seems to be a django bug where you can't exclude null values from a queryset.
        s3_upload.return_value = None
        get_client_public_key_string.return_value = "a_private_key"
        self.default_populated_intervention_date.update(date=None)
        self.default_study_field  # may as well throw this in, shouldn't do anything
        # set up a relative schedule that will need to be checked inside repopulate_relative_...
        self.generate_relative_schedule(self.default_survey, self.default_intervention, days_after=0)
        # run test
        resp = self.smart_post_status_code(200, **self.BASIC_PARAMS)
        response_dict = json.loads(resp.content)
        self.assertEqual("a_private_key", response_dict["client_public_key"])
        self.session_participant.refresh_from_db()
        self.assertTrue(self.session_participant.validate_password(self.NEW_PASSWORD_HASHED))
        self.assertIsInstance(self.default_participant.last_register_user, datetime)
        self.default_populated_intervention_date.refresh_from_db()
        self.assertIsNone(self.default_populated_intervention_date.date)
    
    @patch("api.mobile_api.s3_upload")
    @patch("api.mobile_api.get_client_public_key_string")
    def test_success_bad_device_id_still_works(
        self, get_client_public_key_string: MagicMock, s3_upload: MagicMock
    ):
        # we blanket disabled device id validation
        s3_upload.return_value = None
        get_client_public_key_string.return_value = "a_private_key"
        # unregistered participants have no device id
        params = self.BASIC_PARAMS
        params['device_id'] = "hhhhhhhhhhhhhhhhhhh"
        self.session_participant.update(device_id="aosnetuhsaronceu")
        resp = self.smart_post_status_code(200, **params)
        response_dict = json.loads(resp.content)
        self.assertEqual("a_private_key", response_dict["client_public_key"])
        self.session_participant.refresh_from_db()
        self.assertTrue(self.session_participant.validate_password(self.NEW_PASSWORD_HASHED))
    
    @patch("api.mobile_api.s3_upload")
    @patch("api.mobile_api.get_client_public_key_string")
    def test_bad_password(
        self, get_client_public_key_string: MagicMock, s3_upload: MagicMock
    ):
        s3_upload.return_value = None
        get_client_public_key_string.return_value = "a_private_key"
        params = self.BASIC_PARAMS
        params['password'] = "nope!"
        self.skip_next_device_tracker_params
        resp = self.smart_post_status_code(403, **params)
        self.assertEqual(resp.content, b"")
        self.session_participant.refresh_from_db()
        self.assertFalse(self.session_participant.validate_password(self.NEW_PASSWORD_HASHED))
    
    @patch("api.mobile_api.s3_upload")
    @patch("api.mobile_api.get_client_public_key_string")
    def test_study_easy_enrollment(
        self, get_client_public_key_string: MagicMock, s3_upload: MagicMock
    ):
        s3_upload.return_value = None
        get_client_public_key_string.return_value = "a_private_key"
        params = self.BASIC_PARAMS
        self.default_study.update(easy_enrollment=True)
        params['password'] = "nope!"
        resp = self.smart_post_status_code(200, **params)
        response_dict = json.loads(resp.content)
        self.assertEqual("a_private_key", response_dict["client_public_key"])
        self.session_participant.refresh_from_db()
        self.assertTrue(self.session_participant.validate_password(self.NEW_PASSWORD_HASHED))
    
    @patch("api.mobile_api.s3_upload")
    @patch("api.mobile_api.get_client_public_key_string")
    def test_participant_easy_enrollment(
        self, get_client_public_key_string: MagicMock, s3_upload: MagicMock
    ):
        s3_upload.return_value = None
        get_client_public_key_string.return_value = "a_private_key"
        params = self.BASIC_PARAMS
        self.default_participant.update(easy_enrollment=True)
        params['password'] = "nope!"
        resp = self.smart_post_status_code(200, **params)
        response_dict = json.loads(resp.content)
        self.assertEqual("a_private_key", response_dict["client_public_key"])
        self.session_participant.refresh_from_db()
        self.assertTrue(self.session_participant.validate_password(self.NEW_PASSWORD_HASHED))
    
    def test_deleted_participant(self):
        self.INJECT_DEVICE_TRACKER_PARAMS = False
        self.default_participant.update(deleted=True)
        response = self.smart_post_status_code(403)
        self.assertEqual(response.content, b"")
        self.INJECT_DEVICE_TRACKER_PARAMS = True


class TestGetLatestDeviceSettings(ParticipantSessionTest):
    ENDPOINT_NAME = "mobile_api.get_latest_device_settings"
    
    def test_success(self):
        self.assertIsNone(self.default_participant.last_get_latest_device_settings)
        response = self.smart_post_status_code(200)
        response_json_loaded = json.loads(response.content.decode())
        self.assertEqual(self.default_study.device_settings.export(), response_json_loaded)
        self.default_participant.refresh_from_db()
        self.assertIsNotNone(self.default_participant.last_get_latest_device_settings)
        self.assertIsInstance(self.default_participant.last_get_latest_device_settings, datetime)
    
    def test_deleted_participant(self):
        self.INJECT_DEVICE_TRACKER_PARAMS = False
        self.default_participant.update(deleted=True)
        response = self.smart_post_status_code(403)
        self.assertEqual(response.content, b"")
        self.INJECT_DEVICE_TRACKER_PARAMS = True


class TestMobileUpload(ParticipantSessionTest):
    # FIXME: This test needs better coverage
    ENDPOINT_NAME = "mobile_api.upload"
    
    @classmethod
    def setUpClass(cls) -> None:
        # pycrypto (and probably pycryptodome) requires that we re-seed the random number generation
        # if we run using the --parallel directive.
        from Cryptodome import Random as old_Random
        old_Random.atfork()
        return super().setUpClass()
    
    # these are some generated keys that are part of the codebase, because generating them is slow
    # and potentially a source of error.
    with open(f"{BEIWE_PROJECT_ROOT}/tests/files/private_key", 'rb') as f:
        PRIVATE_KEY = get_RSA_cipher(f.read())
    with open(f"{BEIWE_PROJECT_ROOT}/tests/files/public_key", 'rb') as f:
        PUBLIC_KEY = get_RSA_cipher(f.read())
    
    @property
    def assert_no_files_to_process(self):
        self.assertEqual(FileToProcess.objects.count(), 0)
    
    @property
    def assert_one_file_to_process(self):
        self.assertEqual(FileToProcess.objects.count(), 1)
    
    def test_bad_file_names(self):
        self.assert_no_files_to_process
        # responds with 200 code because device deletes file based on return
        self.smart_post_status_code(200)
        self.assert_no_files_to_process
        self.smart_post_status_code(200, file_name="rList")
        self.assert_no_files_to_process
        self.smart_post_status_code(200, file_name="PersistedInstallation")
        self.assert_no_files_to_process
        # valid file extensions: csv, json, mp4, wav, txt, jpg
        self.smart_post_status_code(200, file_name="whatever")
        self.assert_no_files_to_process
        # no file parameter
        self.skip_next_device_tracker_params
        self.smart_post_status_code(400, file_name="whatever.csv")
        self.assert_no_files_to_process
        # correct file key, should fail
        self.smart_post_status_code(200, file="some_content")
        self.assert_no_files_to_process
    
    def test_unregistered_participant(self):
        # fails with 400 if the participant is registered.  This behavior has a side effect of
        # deleting data on the device, which seems wrong.
        self.skip_next_device_tracker_params
        self.smart_post_status_code(400, file_name="whatever.csv")
        self.session_participant.update(unregistered=True)
        self.smart_post_status_code(200, file_name="whatever.csv")
        self.assert_no_files_to_process
    
    def test_file_already_present_as_ftp(self):
        # there is a ~complex file name test, this value will match and cause that test to succeed,
        # which makes the endpoint return early.  This test will crash with the S3 invalid bucket
        # failure mode if there is no match.
        normalized_file_name = f"{self.session_study.object_id}/whatever.csv"
        self.skip_next_device_tracker_params
        self.smart_post_status_code(400, file_name=normalized_file_name)
        ftp = self.generate_file_to_process(normalized_file_name)
        self.smart_post_status_code(400, file_name=normalized_file_name, file=object())
        self.assert_one_file_to_process
        should_be_identical = FileToProcess.objects.first()
        self.assertEqual(ftp.id, should_be_identical.id)
        self.assertEqual(ftp.last_updated, should_be_identical.last_updated)
        self.assert_one_file_to_process
    
    @patch("libs.participant_file_uploads.s3_upload")
    @patch("database.user_models_participant.Participant.get_private_key")
    def test_no_file_content(self, get_private_key: MagicMock, s3_upload: MagicMock):
        self.assertIsNone(self.default_participant.last_upload)
        get_private_key.return_value = self.PRIVATE_KEY
        self.smart_post_status_code(200, file_name="whatever.csv", file="")
        # big fat nothing happens
        self.assert_no_files_to_process
        self.assertEqual(GenericEvent.objects.count(), 0)
        # inserting this test for the last_upload update....
        self.default_participant.refresh_from_db()
        self.assertIsInstance(self.default_participant.last_upload, datetime)
    
    @patch("libs.participant_file_uploads.s3_upload")
    @patch("database.user_models_participant.Participant.get_private_key")
    def test_decryption_key_bad_padding(self, get_private_key: MagicMock, s3_upload: MagicMock):
        get_private_key.return_value = self.PRIVATE_KEY
        self.smart_post_status_code(200, file_name="whatever.csv", file="some_content")
        self.assert_no_files_to_process
        # happens to be bad length decryption key
        self.assertEqual(GenericEvent.objects.count(), 1)
        self.assertIn("Decryption key not 128 bits", GenericEvent.objects.get().note)
    
    @patch("libs.participant_file_uploads.s3_upload")
    @patch("database.user_models_participant.Participant.get_private_key")
    def test_decryption_key_not_base64(self, get_private_key: MagicMock, s3_upload: MagicMock):
        get_private_key.return_value = self.PRIVATE_KEY
        self.smart_post_status_code(200, file_name="whatever.csv", file="some_content/\\")
        self.assert_no_files_to_process
        self.assertEqual(GenericEvent.objects.count(), 1)
        self.assertIn("Key not base64 encoded:", GenericEvent.objects.get().note)
    
    @patch("libs.participant_file_uploads.s3_upload")
    @patch("database.user_models_participant.Participant.get_private_key")
    def test_bad_base64_length(self, get_private_key: MagicMock, s3_upload: MagicMock):
        get_private_key.return_value = self.PRIVATE_KEY
        self.smart_post_status_code(200, file_name="whatever.csv", file=b"some_content1")
        self.assert_no_files_to_process
        self.assertEqual(GenericEvent.objects.count(), 1)
        self.assertIn(
            "invalid length 2 after padding was removed.",
            GenericEvent.objects.get().note
        )
    # TODO: add invalid decrypted key length test...
    
    def test_deleted_participant(self):
        self.INJECT_DEVICE_TRACKER_PARAMS = False
        self.default_participant.update(deleted=True)
        response = self.smart_post_status_code(403)
        self.assertEqual(response.content, b"")
        self.INJECT_DEVICE_TRACKER_PARAMS = True


class TestGraph(ParticipantSessionTest):
    ENDPOINT_NAME = "mobile_pages.fetch_graph"
    
    def test(self):
        # testing this requires setting up fake survey answers to see what renders in the javascript?
        resp = self.smart_post_status_code(200)
        self.assert_present("Rendered graph for user", resp.content)
    
    def test_deleted_participant(self):
        self.INJECT_DEVICE_TRACKER_PARAMS = False
        self.default_participant.update(deleted=True)
        response = self.smart_post_status_code(403)
        self.assertEqual(response.content, b"")
        self.INJECT_DEVICE_TRACKER_PARAMS = True


#
## tableau_api
#

class TestWebDataConnector(SmartRequestsTestCase):
    ENDPOINT_NAME = "tableau_api.web_data_connector"
    
    def test(self):
        resp = self.smart_get(self.session_study.object_id)
        content = resp.content.decode()
        for field in FINAL_SERIALIZABLE_FIELDS:
            self.assert_present(field.name, content)

#
## push_notifications_api
#
class TestPushNotificationSetFCMToken(ParticipantSessionTest):
    ENDPOINT_NAME = "push_notifications_api.set_fcm_token"
    
    def test_no_params_bug(self):
        # this was a 1 at start of writing tests due to a bad default value in the declaration.
        self.assertEqual(ParticipantFCMHistory.objects.count(), 0)
        
        self.session_participant.update(push_notification_unreachable_count=1)
        # FIXME: no parameters results in a 204, it should fail with a 400.
        self.smart_post_status_code(204)
        # FIXME: THIS ASSERT IS A BUG! it should be 1!
        self.assertEqual(ParticipantFCMHistory.objects.count(), 0)
    
    def test_unregister_existing(self):
        # create a new "valid" registration token (not unregistered)
        token_1 = ParticipantFCMHistory(
            participant=self.session_participant, token="some_value", unregistered=None
        )
        token_1.save()
        self.smart_post(fcm_token="some_new_value")
        token_1.refresh_from_db()
        self.assertIsNotNone(token_1.unregistered)
        token_2 = ParticipantFCMHistory.objects.last()
        self.assertNotEqual(token_1.id, token_2.id)
        self.assertIsNone(token_2.unregistered)
    
    def test_reregister_existing_valid(self):
        self.assertIsNone(self.default_participant.last_set_fcm_token)
        # create a new "valid" registration token (not unregistered)
        token = ParticipantFCMHistory(
            participant=self.session_participant, token="some_value", unregistered=None
        )
        token.save()
        # test only the one token exists
        first_time = token.last_updated
        self.smart_post(fcm_token="some_value")
        # test remains unregistered, but token still updated
        token.refresh_from_db()
        second_time = token.last_updated
        self.assertIsNone(token.unregistered)
        self.assertNotEqual(first_time, second_time)
        # test last_set_fcm_token was set
        self.session_participant.refresh_from_db()
        self.assertIsInstance(self.default_participant.last_set_fcm_token, datetime)
    
    def test_reregister_existing_unregister(self):
        # create a new "valid" registration token (not unregistered)
        token = ParticipantFCMHistory(
            participant=self.session_participant, token="some_value", unregistered=timezone.now()
        )
        token.save()
        # test only the one token exists
        first_time = token.last_updated
        self.smart_post(fcm_token="some_value")
        # test is to longer unregistered, and was updated
        token.refresh_from_db()
        second_time = token.last_updated
        self.assertIsNone(token.unregistered)
        self.assertNotEqual(first_time, second_time)

#
## push_notifications_api
#
class TestResendPushNotifications(ResearcherSessionTest):
    ENDPOINT_NAME = "push_notifications_api.resend_push_notification"
    
    def do_post(self):
        # the post operation that all the tests use...
        return self.smart_post_status_code(
            302,
            self.session_study.pk,
            self.default_participant.patient_id,
            survey_id=self.default_survey.pk
        )
    
    def test_bad_fcm_token(self):  # check_firebase_instance: MagicMock):
        self.set_session_study_relation(ResearcherRole.researcher)
        token = self.generate_fcm_token(self.default_participant)
        token.update(unregistered=timezone.now())
        self.assertEqual(self.default_participant.fcm_tokens.count(), 1)
        self.do_post()
        self.assertEqual(self.default_participant.fcm_tokens.count(), 1)
        archived_event = self.default_participant.archived_events.latest("created_on")
        self.assertEqual(archived_event.status, DEVICE_HAS_NO_REGISTERED_TOKEN)
        self.validate_scheduled_event(archived_event)
    
    def test_no_fcm_token(self):  # check_firebase_instance: MagicMock):
        self.set_session_study_relation(ResearcherRole.researcher)
        self.assertEqual(self.default_participant.fcm_tokens.count(), 0)
        self.do_post()
        self.assertEqual(self.default_participant.fcm_tokens.count(), 0)
        archived_event = self.default_participant.archived_events.latest("created_on")
        self.assertEqual(archived_event.status, DEVICE_HAS_NO_REGISTERED_TOKEN)
        self.validate_scheduled_event(archived_event)
    
    def test_no_firebase_creds(self):  # check_firebase_instance: MagicMock):
        self.set_session_study_relation(ResearcherRole.researcher)
        self.generate_fcm_token(self.default_participant)
        self.do_post()
        archived_event = self.default_participant.archived_events.latest("created_on")
        self.assertEqual(archived_event.status, PUSH_NOTIFICATIONS_NOT_CONFIGURED)
        self.validate_scheduled_event(archived_event)
    
    def test_400(self):
        # missing survey_id
        self.set_session_study_relation(ResearcherRole.researcher)
        self.generate_fcm_token(self.default_participant)
        self.smart_post_status_code(400, self.session_study.pk, self.default_participant.patient_id)
    
    @patch("api.push_notifications_api.send_push_notification")
    @patch("api.push_notifications_api.check_firebase_instance")
    def test_mocked_firebase_valueerror_error_1(
        self, check_firebase_instance: MagicMock, send_push_notification: MagicMock
    ):
        # manually invoke some other ValueError to validate that dumb logic.
        check_firebase_instance.return_value = True
        send_push_notification.side_effect = ValueError('something exploded')
        self.set_session_study_relation(ResearcherRole.researcher)
        self.generate_fcm_token(self.default_participant)
        self.do_post()
        archived_event = self.default_participant.archived_events.latest("created_on")
        self.assertIn(MESSAGE_SEND_FAILED_UNKNOWN, archived_event.status)
        self.validate_scheduled_event(archived_event)
    
    @patch("api.push_notifications_api.check_firebase_instance")
    def test_mocked_firebase_valueerror_2(self, check_firebase_instance: MagicMock):
        # by failing to patch messages.send we trigger a valueerror because firebase creds aren't
        #  present is not configured, it is passed to the weird firebase clause
        check_firebase_instance.return_value = True
        self.set_session_study_relation(ResearcherRole.researcher)
        self.generate_fcm_token(self.default_participant)
        self.do_post()
        archived_event = self.default_participant.archived_events.latest("created_on")
        self.assertIn("The default Firebase app does not exist.", archived_event.status)
        self.assertIn("Firebase Error,", archived_event.status)
        self.validate_scheduled_event(archived_event)
    
    @patch("api.push_notifications_api.send_push_notification")
    @patch("api.push_notifications_api.check_firebase_instance")
    def test_mocked_firebase_unregistered_error(
        self, check_firebase_instance: MagicMock, send_push_notification: MagicMock
    ):
        # manually invoke some other ValueError to validate that dumb logic.
        check_firebase_instance.return_value = True
        from firebase_admin.messaging import UnregisteredError
        err_msg = 'UnregisteredError occurred'
        send_push_notification.side_effect = UnregisteredError(err_msg)
        self.set_session_study_relation(ResearcherRole.researcher)
        self.generate_fcm_token(self.default_participant)
        self.do_post()
        archived_event = self.default_participant.archived_events.latest("created_on")
        self.assertIn("Firebase Error,", archived_event.status)
        self.assertIn(err_msg, archived_event.status)
        self.validate_scheduled_event(archived_event)
    
    @patch("api.push_notifications_api.send_push_notification")
    @patch("api.push_notifications_api.check_firebase_instance")
    def test_mocked_generic_error(
        self, check_firebase_instance: MagicMock, send_push_notification: MagicMock
    ):
        # mock generic error on sending the notification
        check_firebase_instance.return_value = True
        send_push_notification.side_effect = Exception('something exploded')
        self.set_session_study_relation(ResearcherRole.researcher)
        self.generate_fcm_token(self.default_participant)
        self.do_post()
        archived_event = self.default_participant.archived_events.latest("created_on")
        self.assertEqual(MESSAGE_SEND_FAILED_UNKNOWN, archived_event.status)
        self.validate_scheduled_event(archived_event)
    
    @patch("api.push_notifications_api.check_firebase_instance")
    @patch("api.push_notifications_api.send_push_notification")
    def test_mocked_success(self, check_firebase_instance: MagicMock, messaging: MagicMock):
        check_firebase_instance.return_value = True
        self.set_session_study_relation(ResearcherRole.researcher)
        self.generate_fcm_token(self.default_participant)
        self.do_post()
        archived_event = self.default_participant.archived_events.latest("created_on")
        self.assertIn(MESSAGE_SEND_SUCCESS, archived_event.status)
        self.validate_scheduled_event(archived_event)
    
    @patch("api.push_notifications_api.check_firebase_instance")
    @patch("api.push_notifications_api.send_push_notification")
    def test_mocked_success_ios(self, check_firebase_instance: MagicMock, messaging: MagicMock):
        check_firebase_instance.return_value = True
        self.default_participant.update(os_type=IOS_API)  # the default os type is android
        self.set_session_study_relation(ResearcherRole.researcher)
        self.generate_fcm_token(self.default_participant)
        self.do_post()
        archived_event = self.default_participant.archived_events.latest("created_on")
        self.assertIn(MESSAGE_SEND_SUCCESS, archived_event.status)
        self.validate_scheduled_event(archived_event)
    
    def validate_scheduled_event(self, archived_event: ArchivedEvent):
        # the scheduled event needs to have some specific qualities
        self.assertEqual(ScheduledEvent.objects.count(), 1)
        one_time_schedule = ScheduledEvent.objects.first()
        self.assertEqual(one_time_schedule.survey_id, self.default_survey.id)
        self.assertEqual(one_time_schedule.checkin_time, None)
        self.assertEqual(one_time_schedule.deleted, True)  # important, don't resend
        self.assertEqual(one_time_schedule.most_recent_event.id, archived_event.id)

#
## forest_pages
#

# FIXME: make a real test...
class TestForestAnalysisProgress(ResearcherSessionTest):
    ENDPOINT_NAME = "forest_pages.analysis_progress"
    
    def test(self):
        # hey it loads...
        self.set_session_study_relation(ResearcherRole.researcher)
        for _ in range(10):
            self.generate_participant(self.session_study)
        # print(Participant.objects.count())
        self.smart_get(self.session_study.id)


# class TestForestCreateTasks(ResearcherSessionTest):
#     ENDPOINT_NAME = "forest_pages.create_tasks"

#     def test(self):
#         self.smart_get()


# class TestForestTaskLog(ResearcherSessionTest):
#     ENDPOINT_NAME = "forest_pages.task_log"

#     def test(self):
#         self.smart_get()


# class TestForestDownloadTaskLog(ResearcherSessionTest):
#     ENDPOINT_NAME = "forest_pages.download_task_log"

#     def test(self):
#         self.smart_get()


# class TestForestCancelTask(ResearcherSessionTest):
#     ENDPOINT_NAME = "forest_pages.cancel_task"

#     def test(self):
#         self.smart_get()


# class TestForestDownloadTaskData(ResearcherSessionTest):
#     ENDPOINT_NAME = "forest_pages.download_task_data"

#     def test(self):
#         self.smart_get()
