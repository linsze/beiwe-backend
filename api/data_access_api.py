import json
from datetime import datetime

from django.db.models import QuerySet
from django.http.response import StreamingHttpResponse
from django.views.decorators.http import require_http_methods

from authentication.data_access_authentication import api_study_credential_check
from config.constants import ALL_DATA_STREAMS, API_TIME_FORMAT
from database.data_access_models import ChunkRegistry, PipelineUpload
from database.user_models import Participant
from libs.internal_types import ApiStudyResearcherRequest
from libs.streaming_zip import zip_generator, zip_generator_for_pipeline
from middleware.abort_middleware import abort


chunk_fields = ("pk", "participant_id", "data_type", "chunk_path", "time_bin", "chunk_hash",
                "participant__patient_id", "study_id", "survey_id", "survey__object_id")

@require_http_methods(['POST', "GET"])
@api_study_credential_check(block_test_studies=True)
def get_data(request: ApiStudyResearcherRequest):
    """ Required: access key, access secret, study_id
    JSON blobs: data streams, users - default to all
    Strings: date-start, date-end - format as "YYYY-MM-DDThh:mm:ss"
    optional: top-up = a file (registry.dat)
    cases handled:
        missing creds or study, invalid researcher or study, researcher does not have access
        researcher creds are invalid
        (Flask automatically returns a 400 response if a parameter is accessed
        but does not exist in request.POST() )
    Returns a zip file of all data files found by the query. """

    query_args = {}
    determine_data_streams_for_db_query(request, query_args)
    determine_users_for_db_query(request, query_args)
    determine_time_range_for_db_query(request, query_args)

    # Do query! (this is actually a generator)
    get_these_files = handle_database_query(request.api_study.pk, query_args, registry_dict=parse_registry(request))

    # If the request is from the web form we need to indicate that it is an attachment,
    # and don't want to create a registry file.
    # Oddly, it is the presence of  mimetype=zip that causes the streaming response to actually stream.
    if 'web_form' in request.POST:
        return StreamingHttpResponse(
            request,
            zip_generator(get_these_files, construct_registry=False),
            mimetype="zip",
            headers={'Content-Disposition': 'attachment; filename="data.zip"'}
        )
    else:
        return StreamingHttpResponse(
            request,
            zip_generator(get_these_files, construct_registry=True),
            mimetype="zip",
        )


@require_http_methods(["GET", "POST"])
@api_study_credential_check()
def pipeline_data_download(request: ApiStudyResearcherRequest):
    # the following two cases are for difference in content wrapping between the CLI script and
    # the download page.
    if 'tags' in request.POST:
        try:
            tags = json.loads(request.POST['tags'])
        except ValueError:
            tags = request.POST.getlist('tags')
        query = PipelineUpload.objects.filter(study__id=request.api_study.id, tags__tag__in=tags)
    else:
        query = PipelineUpload.objects.filter(study__id=request.api_study.id)

    return StreamingHttpResponse(
        request,
        zip_generator_for_pipeline(query),
        mimetype="zip",
        headers={'Content-Disposition': 'attachment; filename="data.zip"'}
    )


def parse_registry(request: ApiStudyResearcherRequest):
    """ Parses the provided registry.dat file and returns a dictionary of chunk
    file names and hashes.  (The registry file is just a json dictionary containing
    a list of file names and hashes.) """
    registry = request.POST.get("registry", None)
    if registry is None:
        return None

    try:
        ret = json.loads(registry)
    except ValueError:
        return abort(400)

    if not isinstance(ret, dict):
        return abort(400)

    return ret


def str_to_datetime(time_string):
    """ Translates a time string to a datetime object, raises a 400 if the format is wrong."""
    try:
        return datetime.strptime(time_string, API_TIME_FORMAT)
    except ValueError as e:
        if "does not match format" in str(e):
            return abort(400)


#########################################################################################
############################ DB Query For Data Download #################################
#########################################################################################

def determine_data_streams_for_db_query(request: ApiStudyResearcherRequest, query_dict: dict):
    """ Determines, from the html request, the data streams that should go into the database query.
    Modifies the provided query object accordingly, there is no return value
    Throws a 404 if the data stream provided does not exist. """
    if 'data_streams' in request.POST:
        # the following two cases are for difference in content wrapping between
        # the CLI script and the download page.
        try:
            query_dict['data_types'] = json.loads(request.POST['data_streams'])
        except ValueError:
            query_dict['data_types'] = request.POST.getlist('data_streams')

        for data_stream in query_dict['data_types']:
            if data_stream not in ALL_DATA_STREAMS:
                return abort(404)


def determine_users_for_db_query(request: ApiStudyResearcherRequest, query: dict):
    """ Determines, from the html request, the users that should go into the database query.
    Modifies the provided query object accordingly, there is no return value.
    Throws a 404 if a user provided does not exist. """
    if 'user_ids' in request.POST:
        try:
            query['user_ids'] = [user for user in json.loads(request.POST['user_ids'])]
        except ValueError:
            query['user_ids'] = request.POST.getlist('user_ids')

        # Ensure that all user IDs are patient_ids of actual Participants
        if not Participant.objects.filter(patient_id__in=query['user_ids']).count() == len(query['user_ids']):
            return abort(404)


def determine_time_range_for_db_query(request: ApiStudyResearcherRequest, query: dict):
    """ Determines, from the html request, the time range that should go into the database query.
    Modifies the provided query object accordingly, there is no return value.
    Throws a 404 if a user provided does not exist. """
    if 'time_start' in request.POST:
        query['start'] = str_to_datetime(request.POST['time_start'])
    if 'time_end' in request.POST:
        query['end'] = str_to_datetime(request.POST['time_end'])


def handle_database_query(study_id: int, query_dict: dict, registry_dict: dict = None) -> QuerySet:
    """ Runs the database query and returns a QuerySet. """
    chunks = ChunkRegistry.get_chunks_time_range(study_id, **query_dict)

    if not registry_dict:
        return chunks.values(*chunk_fields)

    # If there is a registry, we need to filter on the chunks
    else:
        # Get all chunks whose path and hash are both in the registry
        possible_registered_chunks = (
            chunks
                .filter(chunk_path__in=registry_dict, chunk_hash__in=registry_dict.values())
                .values('pk', 'chunk_path', 'chunk_hash')
        )

        # determine those chunks that we do not want present in the download
        # (get a list of pks that have hashes that don't match the database)
        registered_chunk_pks = [
            c['pk'] for c in possible_registered_chunks
            if registry_dict[c['chunk_path']] == c['chunk_hash']
        ]

        # add the exclude and return the queryset
        return chunks.exclude(pk__in=registered_chunk_pks).values(*chunk_fields)
