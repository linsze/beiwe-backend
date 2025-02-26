import json

from django.contrib import messages
from django.db.models import ProtectedError
from django.db.models.expressions import ExpressionWrapper
from django.db.models.fields import BooleanField
from django.db.models.functions.text import Lower
from django.db.models.query import Prefetch
from django.db.models.query_utils import Q
from django.http import FileResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_http_methods, require_POST

from authentication.admin_authentication import authenticate_researcher_study_access
from constants.common_constants import API_DATE_FORMAT
from database.schedule_models import Intervention, InterventionDate
from database.study_models import Study, StudyField
from database.user_models_participant import Participant, ParticipantFieldValue
from libs.internal_types import ResearcherRequest
from libs.intervention_utils import (correct_bad_interventions, intervention_survey_data,
    survey_history_export)


@require_POST
@authenticate_researcher_study_access
def study_participants_api(request: ResearcherRequest, study_id: int):
    study: Study = Study.objects.get(pk=study_id)
    correct_bad_interventions(study)

    # `draw` is passed by DataTables. It's automatically incremented, starting with 1 on the page
    # load, and then 2 with the next call to this API endpoint, and so on.
    draw = int(request.POST.get('draw'))
    start = int(request.POST.get('start'))
    length = int(request.POST.get('length'))
    sort_by_column_index = int(request.POST.get('order[0][column]'))
    sort_in_descending_order = request.POST.get('order[0][dir]') == 'desc'
    contains_string = request.POST.get('search[value]')
    total_participants_count = Participant.objects.filter(study_id=study_id).count()
    filtered_participants_count = filtered_participants(study, contains_string).count()
    data = get_values_for_participants_table(
        study, start, length, sort_by_column_index, sort_in_descending_order, contains_string
    )
    
    table_data = {
        "draw": draw,
        "recordsTotal": total_participants_count,
        "recordsFiltered": filtered_participants_count,
        "data": data
    }
    return JsonResponse(table_data, status=200)


@require_http_methods(['GET', 'POST'])
@authenticate_researcher_study_access
def interventions_page(request: ResearcherRequest, study_id=None):
    study: Study = Study.objects.get(pk=study_id)
    # TODO: get rid of dual endpoint pattern, it is a bad idea.
    if request.method == 'GET':
        return render(
            request,
            'study_interventions.html',
            context=dict(
                study=study,
                interventions=study.interventions.all(),
            ),
        )
    
    # slow but safe
    new_intervention = request.POST.get('new_intervention', None)
    if new_intervention:
        intervention, _ = Intervention.objects.get_or_create(study=study, name=new_intervention)
        for participant in study.participants.all():
            InterventionDate.objects.get_or_create(participant=participant, intervention=intervention)
    
    return redirect(f'/interventions/{study.id}')


@require_http_methods(['GET', 'POST'])
@authenticate_researcher_study_access
def download_study_interventions(request: ResearcherRequest, study_id=None):
    study = get_object_or_404(Study, id=study_id)
    data = intervention_survey_data(study)
    fr = FileResponse(
        json.dumps(data),
        content_type="text/json",
        as_attachment=True,
        filename=f"{study.object_id}_intervention_data.json",
    )
    fr.set_headers(None)  # django is kinda stupid? buh?
    return fr


@require_http_methods(['GET', 'POST'])
@authenticate_researcher_study_access
def download_study_survey_history(request: ResearcherRequest, study_id=None):
    study = get_object_or_404(Study, id=study_id)
    fr = FileResponse(
        survey_history_export(study).decode(),  # okay, whatever, it needs to be a string, not bytes
        content_type="text/json",
        as_attachment=True,
        filename=f"{study.object_id}_surveys_history_data.json",
    )
    fr.set_headers(None)  # django is still stupid?
    return fr


@require_POST
@authenticate_researcher_study_access
def delete_intervention(request: ResearcherRequest, study_id=None):
    """Deletes the specified Intervention. Expects intervention in the request body."""
    study = Study.objects.get(pk=study_id)
    intervention_id = request.POST.get('intervention')
    if intervention_id:
        try:
            intervention = Intervention.objects.get(id=intervention_id)
        except Intervention.DoesNotExist:
            intervention = None
        try:
            if intervention:
                intervention.delete()
        except ProtectedError:
            messages.warning("This Intervention can not be removed because it is already in use")
    
    return redirect(f'/interventions/{study.id}')


@require_POST
@authenticate_researcher_study_access
def edit_intervention(request: ResearcherRequest, study_id=None):
    """ Edits the name of the intervention. Expects intervention_id and edit_intervention in the
    request body """
    study = Study.objects.get(pk=study_id)
    intervention_id = request.POST.get('intervention_id', None)
    new_name = request.POST.get('edit_intervention', None)
    if intervention_id:
        try:
            intervention = Intervention.objects.get(id=intervention_id)
        except Intervention.DoesNotExist:
            intervention = None
        if intervention and new_name:
            intervention.name = new_name
            intervention.save()
    
    return redirect(f'/interventions/{study.id}')


@require_http_methods(['GET', 'POST'])
@authenticate_researcher_study_access
def study_fields(request: ResearcherRequest, study_id=None):
    study = Study.objects.get(pk=study_id)
    # TODO: get rid of dual endpoint pattern, it is a bad idea.
    if request.method == 'GET':
        return render(
            request,
            'study_custom_fields.html',
            context=dict(
                study=study,
                fields=study.fields.all(),
            ),
        )
    
    new_field = request.POST.get('new_field', None)
    if new_field:
        study_field, _ = StudyField.objects.get_or_create(study=study, field_name=new_field)
        for participant in study.participants.all():
            ParticipantFieldValue.objects.create(participant=participant, field=study_field)
    
    return redirect(f'/study_fields/{study.id}')


@require_POST
@authenticate_researcher_study_access
def delete_field(request: ResearcherRequest, study_id=None):
    """Deletes the specified Custom Field. Expects field in the request body."""
    study = Study.objects.get(pk=study_id)
    field = request.POST.get('field', None)
    if field:
        try:
            study_field = StudyField.objects.get(study=study, id=field)
        except StudyField.DoesNotExist:
            study_field = None
        
        try:
            if study_field:
                study_field.delete()
        except ProtectedError:
            messages.warning("This field can not be removed because it is already in use")
    
    return redirect(f'/study_fields/{study.id}')


@require_POST
@authenticate_researcher_study_access
def edit_custom_field(request: ResearcherRequest, study_id=None):
    """Edits the name of a Custom field. Expects field_id anf edit_custom_field in request body"""
    field_id = request.POST.get("field_id")
    new_field_name = request.POST.get("edit_custom_field")
    if field_id:
        try:
            field = StudyField.objects.get(id=field_id)
        except StudyField.DoesNotExist:
            field = None
        if field and new_field_name:
            field.field_name = new_field_name
            field.save()
    
    # this apparent insanity is a hopefully unnecessary confirmation of the study id
    return redirect(f'/study_fields/{Study.objects.get(pk=study_id).id}')


def get_values_for_participants_table(
    study: Study, start: int, length: int, sort_by_column_index: int,
    sort_in_descending_order: bool, contains_string: str
):
    """ Logic to get paginated information of the participant list on a study. """
    # If we need to optimize this function that probably requires the set up of a lookup
    # dictionary instead of querying the database for every participant's field values.
    # This isn't currently implemented because there are only ~15 participants per page rendered
    # x = ParticipantFieldValue.objects.filter(participant__study=self).values_list(
    #     "participant_id", "field__field_name", "value"
    # )
    # participant_field_values = defaultdict(dict)
    # for participant_id, field_name, value in x:
    #     participant_field_values[participant_id][field_name] = value
    
    # TODO: this code can be substantially simplified. Move sorting to python, ExpressionWrapper is
    #   needlessly complex and may be using the incorrect field (unclear, the names got screwed up
    #   from their original meanings), convert to values_list, drop the prefetch entirely and make
    #   the intervention dates a separate query into a lookup dict.
    # In fact some sorting has already been moved to python.
    BASIC_COLUMNS = ['created_on', 'patient_id', 'registered', 'os_type']
    HAS_NO_DEVICE_ID = ExpressionWrapper(~Q(device_id=''), output_field=BooleanField())  # ~ is the not operator
    
    sort_by_column = 'patient_id' if sort_by_column_index >= len(BASIC_COLUMNS) else BASIC_COLUMNS[sort_by_column_index]
    sort_by_column = f"-{sort_by_column}" if sort_in_descending_order else sort_by_column
    
    # since field names may not be populated, we need a reference list of all field names
    # ordered to match the ordering on the rendering page.
    field_names_ordered = list(
        study.fields.values_list("field_name", flat=True).order_by(Lower('field_name'))
    )
    
    # Prefetch intervention dates, sorted case-insensitively by_b name
    query = filtered_participants(study, contains_string)
    query = query.annotate(registered=HAS_NO_DEVICE_ID)
    query = query.order_by(sort_by_column)  # must be after the annotate to allow registered sorting
    query = query.prefetch_related(
        Prefetch(
            'intervention_dates',
            queryset=InterventionDate.objects.order_by(Lower('intervention__name'))
        )
    )
    
    # Get the list of the basic columns that are present in every study, convert the created_on
    # into a string in YYYY-MM-DD format, add intervention dates (sorted in prefetch), custom fields.
    participants_data = []
    
    for p in query[start:start + length]:
        # order matters, must match the order of the columns in the table
        participant_values = [p.created_on.strftime(API_DATE_FORMAT), p.patient_id, p.registered, p.os_type]
        
        # a participant has all intervention dates, even if they are not populated yet.
        for int_date in p.intervention_dates.values_list("date", flat=True):
            participant_values.append(int_date.strftime(API_DATE_FORMAT) if int_date else "")
        
        # a participant may not have all custom field values populated, so we need to use a
        # reference in order to fill empty string values where they [don't] exist.
        field_values = dict(p.field_values.values_list("field__field_name", "value"))
        for field_name in field_names_ordered:
            participant_values.append(
                field_values[field_name] if field_name in field_values else ""
            )
        participants_data.append(participant_values)
    
    # guarantees: all rows have the same number of columns, all values are strings.
    if sort_by_column_index >= len(BASIC_COLUMNS):
        participants_data.sort(key=lambda row: row[sort_by_column_index], reverse=sort_in_descending_order)
    return participants_data


def filtered_participants(study: Study, contains_string: str):
    """ Searches for participants with lowercase matches on os_type and patient_id, excludes deleted participants. """
    return Participant.objects.filter(study_id=study.id) \
            .filter(Q(patient_id__icontains=contains_string) | Q(os_type__icontains=contains_string)) \
            .exclude(deleted=True)
