# participant device os
from config.settings import DATA_DELETION_USERTYPE


IOS_API = "IOS"
ANDROID_API = "ANDROID"
NULL_OS = ''

OS_TYPE_CHOICES = (
    (IOS_API, IOS_API),
    (ANDROID_API, ANDROID_API),
    (NULL_OS, NULL_OS),
)


# Researcher User Types
class ResearcherRole:
    study_admin = "study_admin"
    researcher = "study_researcher"
    # site_admin is not a study _relationship_, but we need a canonical string for it somewhere.
    # You are a site admin if 'site_admin' is true on your Researcher model.
    site_admin = "site_admin"
    no_access = "no_access"


if DATA_DELETION_USERTYPE == ResearcherRole.researcher:
    DATA_DELETION_ALLOWED_RELATIONS = (ResearcherRole.researcher, ResearcherRole.study_admin)
elif DATA_DELETION_USERTYPE == ResearcherRole.study_admin:
    DATA_DELETION_ALLOWED_RELATIONS = (ResearcherRole.study_admin, )
elif DATA_DELETION_USERTYPE == ResearcherRole.site_admin:
    DATA_DELETION_ALLOWED_RELATIONS = tuple()
else:
    raise Exception(f"DATA_DELETION_USERTYPE is set to an invalid value: {DATA_DELETION_USERTYPE}")

ALL_RESEARCHER_TYPES = (ResearcherRole.study_admin, ResearcherRole.researcher)


# researcher session constants
SESSION_NAME = "researcher_username"
EXPIRY_NAME = "expiry"
SESSION_UUID = "session_uuid"
