from datetime import date, datetime, tzinfo
from typing import Dict

from django.contrib import messages
from django.core.paginator import EmptyPage, Paginator
from django.db.models import F
from django.http.response import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_GET, require_http_methods

from api.participant_administration import add_fields_and_interventions
from authentication.admin_authentication import authenticate_researcher_study_access
from constants.common_constants import API_DATE_FORMAT
from constants.message_strings import PARTICIPANT_LOCKED
from constants.user_constants import DATA_DELETION_ALLOWED_RELATIONS
from database.schedule_models import ArchivedEvent
from database.study_models import Study
from database.user_models_participant import Participant
from libs.firebase_config import check_firebase_instance
from libs.http_utils import easy_url, really_nice_time_format_with_tz
from libs.internal_types import ArchivedEventQuerySet, ResearcherRequest
from libs.schedules import repopulate_all_survey_scheduled_events


@require_GET
@authenticate_researcher_study_access
def notification_history(request: ResearcherRequest, study_id: int, patient_id: str):
    # use the provided study id because authentication already validated it
    participant = get_object_or_404(Participant, patient_id=patient_id)
    study = get_object_or_404(Study, pk=study_id)
    page_number = request.GET.get('page', 1)
    per_page = request.GET.get('per_page', 100)
    
    archived_events = Paginator(query_values_for_notification_history(participant.id), per_page)
    try:
        archived_events_page = archived_events.page(page_number)
    except EmptyPage:
        return HttpResponse(content="", status=404)
    last_page_number = archived_events.page_range.stop - 1
    
    survey_names = get_survey_names_dict(study)
    notification_attempts = [
        get_notification_details(archived_event, study.timezone, survey_names)
        for archived_event in archived_events_page
    ]
    
    conditionally_display_locked_message(request, participant)
    return render(
        request,
        'notification_history.html',
        context=dict(
            participant=participant,
            page=archived_events_page,
            notification_attempts=notification_attempts,
            study=study,
            last_page_number=last_page_number,
            locked=participant.is_dead,
        )
    )


@require_http_methods(['GET', 'POST'])
@authenticate_researcher_study_access
def participant_page(request: ResearcherRequest, study_id: int, patient_id: str):
    # use the provided study id because authentication already validated it
    participant = get_object_or_404(Participant, patient_id=patient_id)
    study = get_object_or_404(Study, pk=study_id)
    
    # safety check, enforce fields and interventions to be present for both page load and edit.
    if not participant.deleted or participant.has_deletion_event:
        add_fields_and_interventions(participant, study)
    
    # FIXME: get rid of dual endpoint pattern, it is a bad idea.
    if request.method == 'GET':
        return render_participant_page(request, participant, study)
    
    end_redirect = redirect(
        easy_url("participant_pages.participant_page", study_id=study_id, patient_id=patient_id)
    )
    
    # update intervention dates for participant
    for intervention in study.interventions.all():
        input_date = request.POST.get(f"intervention{intervention.id}", None)
        intervention_date = participant.intervention_dates.get(intervention=intervention)
        if input_date:
            try:
                intervention_date.update(date=datetime.strptime(input_date, API_DATE_FORMAT).date())
            except ValueError:
                messages.error(request, 'Invalid date format, please use the date selector or YYYY-MM-DD.')
                return end_redirect
    
    # update custom fields dates for participant
    for field in study.fields.all():
        input_id = f"field{field.id}"
        field_value = participant.field_values.get(field=field)
        field_value.update(value=request.POST.get(input_id, None))
    
    # always call through the repopulate everything call, even though we only need to handle
    # relative surveys, the function handles extra cases.
    repopulate_all_survey_scheduled_events(study, participant)
    
    messages.success(request, f'Successfully edited participant {participant.patient_id}.')
    return end_redirect


def render_participant_page(request: ResearcherRequest, participant: Participant, study: Study):
    # to reduce database queries we get all the data across 4 queries and then merge it together.
    # dicts of intervention id to intervention date string, and of field names to value
    # (this was quite slow previously)
    intervention_dates_map = {
        # this is the intervention's id, not the intervention_date's id.
        intervention_id: format_date_or_none(intervention_date)
        for intervention_id, intervention_date in
        participant.intervention_dates.values_list("intervention_id", "date")
    }
    participant_fields_map = {
        name: value for name, value in
        participant.field_values.values_list("field__field_name", "value")
    }
    
    # list of tuples of (intervention id, intervention name, intervention date)
    intervention_data = [
        (intervention.id, intervention.name, intervention_dates_map.get(intervention.id, ""))
        for intervention in study.interventions.order_by("name")
    ]
    # list of tuples of field name, value.
    field_data = [
        (field_id, field_name, participant_fields_map.get(field_name, ""))
        for field_id, field_name
        in study.fields.order_by("field_name").values_list('id', "field_name")
    ]
    
    # dictionary structured for page rendering
    latest_notification_attempt = get_notification_details(
        query_values_for_notification_history(participant.id).first(),
        study.timezone,
        get_survey_names_dict(study)
    )
    
    relation = request.session_researcher.get_study_relation(study.id)
    can_delete = request.session_researcher.site_admin or relation in DATA_DELETION_ALLOWED_RELATIONS
    
    conditionally_display_locked_message(request, participant)
    return render(
        request,
        'participant.html',
        context=dict(
            participant=participant,
            study=study,
            intervention_data=intervention_data,
            field_values=field_data,
            notification_attempts_count=participant.archived_events.count(),
            latest_notification_attempt=latest_notification_attempt,
            push_notifications_enabled_for_ios=check_firebase_instance(require_ios=True),
            push_notifications_enabled_for_android=check_firebase_instance(require_android=True),
            study_easy_enrollment=study.easy_enrollment,
            participant_easy_enrollment=participant.easy_enrollment,
            locked=participant.is_dead,
            can_delete=can_delete,
        )
    )


def query_values_for_notification_history(participant_id) -> ArchivedEventQuerySet:
    return (
        ArchivedEvent.objects
        .filter(participant_id=participant_id)
        .order_by('-created_on')
        .annotate(
            survey_id=F('survey_archive__survey'), survey_version=F('survey_archive__archive_start')
        )
        .values(
            'scheduled_time', 'created_on', 'survey_id', 'survey_version', 'schedule_type', 'status'
        )
    )


def get_survey_names_dict(study: Study):
    survey_names = {}
    for survey in study.surveys.all():
        if survey.name:
            survey_names[survey.id] = survey.name
        else:
            survey_names[survey.id] =\
                ("Audio Survey " if survey.survey_type == 'audio_survey' else "Survey ") + survey.object_id
    
    return survey_names


def get_notification_details(archived_event: Dict, study_timezone: tzinfo, survey_names: Dict):
    
    notification = {}
    if archived_event is not None:
        notification['scheduled_time'] = really_nice_time_format_with_tz(archived_event['scheduled_time'], study_timezone)
        notification['attempted_time'] = really_nice_time_format_with_tz(archived_event['created_on'], study_timezone)
        notification['survey_name'] = survey_names[archived_event['survey_id']]
        notification['survey_id'] = archived_event['survey_id']
        notification['survey_version'] = archived_event['survey_version'].strftime('%Y-%m-%d')
        notification['schedule_type'] = archived_event['schedule_type']
        notification['status'] = archived_event['status']
    
    return notification


def format_date_or_none(d: date) -> str:
    # tiny function that broke scanability of the real code....
    return d.strftime(API_DATE_FORMAT) if isinstance(d, date) else ""


def conditionally_display_locked_message(request: ResearcherRequest, participant: Participant):
    """ Displays a warning message if the participant is locked. """
    if participant.is_dead:
        messages.warning(request, PARTICIPANT_LOCKED.format(patient_id=participant.patient_id))
