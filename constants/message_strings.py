# Do not bother observing a line limit on this file, please view in wrapped text mode in your ide.

## System Admin Pages

ALERT_ANDROID_DELETED_TEXT = \
    """
    <h3>Stored Android Firebase credentials have been removed if they existed!</h3>
    <p>All registered android apps will be updated as they connect. That process may take some time</p>
    """

ALERT_ANDROID_SUCCESS_TEXT = \
    """
    <h3>New android credentials were received!</h3>
    <p>All registered android apps will be updated as they connect. That process may take some time</p>
    """

ALERT_ANDROID_VALIDATION_FAILED_TEXT = \
    """
    <div class="alert alert-danger" role="alert">
        <h3>There was an error in the processing the new android credentials!</h3>
        <p>We are expecting a json file with a "project_info" field and "project_id"</p>
    </div>
    """

ALERT_DECODE_ERROR_TEXT = \
    """
    <div class="alert alert-danger" role="alert">
        <h3>There was an error in the encoding of the new credentials file!</h3>
        <p>We were unable to read the uploaded file. Make sure that the credentials are saved in a plaintext format
        with an extension like ".txt" or ".json", and not a format like ".pdf" or ".docx"</p>
    </div>
    """

ALERT_EMPTY_TEXT = \
    """
    <div class="alert alert-danger" role="alert">
        <h3>There was an error in the processing the new credentials!</h3>
        <p>You have selected no file or an empty file. If you just want to remove credentials, use the
        delete button</p>
        <p>The previous credentials, if they existed, have not been removed</p>
    </div>
    """

ALERT_FIREBASE_DELETED_TEXT = \
    """
    <h3>All backend Firebase credentials have been deleted if they existed!</h3>
        <p>Note that this does not include IOS and Android app credentials, these must be deleted separately if
        desired</p>
    """

ALERT_IOS_DELETED_TEXT = \
    """
    <h3>Stored IOS Firebase credentials have been removed if they existed!</h3>
    <p>All registered IOS apps will be updated as they connect. That process may take some time</p>
    """

ALERT_IOS_SUCCESS_TEXT = \
    """
    <h3>New IOS credentials were received!</h3>
    <p>All registered IOS apps will be updated as they connect. That process may take some time</p>
    """

ALERT_IOS_VALIDATION_FAILED_TEXT = \
    """
    <div class="alert alert-danger" role="alert">
        <h3>There was an error in the processing the new IOS credentials!</h3>
        <p>We are expecting a plist file with at least the "API_KEY" present.</p>
    </div>
    """

ALERT_MISC_ERROR_TEXT = \
    """
    <div class="alert alert-danger" role="alert">
        <h3>There was an error in the processing the new credentials!</h3>
    </div>
    """

ALERT_SUCCESS_TEXT = \
    """<h3>New firebase credentials have been received!</h3>"""


ALERT_SPECIFIC_ERROR_TEXT = \
    """
    <div class="alert alert-danger" role="alert">
        <h3>{error_message}</h3>
    </div>    """


## Admin Pages
RESET_DOWNLOAD_API_CREDENTIALS_MESSAGE = "Your Data-Download API access credentials have been reset."
NEW_API_KEY_MESSAGE = "New Tableau API credentials have been generated for you!"
PASSWORD_WILL_EXPIRE = "Your password will expire in {days} days, reset it to clear this reminder."
PASSWORD_EXPIRED = "Your password has expired, please reset your password."
PASSWORD_RESET_FORCED = "You have had your password administratively reset, please set a new password."
PASSWORD_RESET_FAIL_SITE_ADMIN = "You cannot manually set a password of a site admin. If you must do so please contact your system administrator."
PASSWORD_RESET_SITE_ADMIN = "Site Administrators must reset their passwords to ensure they are at least 20 characters in length."
PASSWORD_RESET_TOO_SHORT = "A study you are authorized on has a new minimum password length requirement, update your password to continue."

## mfa notices
MFA_CONFIGURATION_REQUIRED = "You must configure MFA before you can use the site."
MFA_LOGIN_MISSING = "MFA code required, try again."
MFA_LOGIN_WRONG = "Incorrect MFA code, try again."
MFA_LOGIN_6_DIGITS = "MFA code must be 6 digits long."
MFA_DIGITS_ONLY = "MFA code must consist of digits."
MFA_RESET_BAD_PERMISSIONS = "You do not have permission to reset this researcher's MFA token."
MFA_SELF_NO_PASSWORD = "No password provided"
MFA_SELF_BAD_PASSWORD = "Invalid Password"
MFA_SELF_SUCCESS = "MFA has been enabled for your account. Use the QR Code below to configure your authenticator app, a one-time-password will now be required the next time you log in."
MFA_SELF_DISABLED = "MFA has been disabled for your account."

# self password reset
PASSWORD_RESET_SUCCESS = "Your password has been reset!"
WRONG_CURRENT_PASSWORD = "The Current Password you have entered is invalid"
NEW_PASSWORD_MISMATCH = "New Password does not match Confirm New Password"
NEW_PASSWORD_N_LONG = "Your New Password must be at least {length} characters long."
NEW_PASSWORD_RULES_FAIL = "Your New Password must contain at least one symbol, one number, one lowercase, and one uppercase character."

# tableau key messages
TABLEAU_NO_MATCHING_API_KEY = "No matching API key found to disable"
TABLEAU_API_KEY_IS_DISABLED = "This API key has already been disabled:"
TABLEAU_API_KEY_NOW_DISABLED = "The API key {key} is now disabled"

## Mobile API
DECRYPTION_KEY_ERROR_MESSAGE = "This file did not contain a valid decryption key and could not be processed."
DECRYPTION_KEY_ADDITIONAL_MESSAGE = "This is an open bug: github.com/onnela-lab/beiwe-backend/issues/186"
S3_FILE_PATH_UNIQUE_CONSTRAINT_ERROR_1 = "File to process with this S3 file path already exists"
S3_FILE_PATH_UNIQUE_CONSTRAINT_ERROR_2 = "duplicate key value violates unique constraint"
UNKNOWN_ERROR = "AN UNKNOWN ERROR OCCURRED."
INVALID_EXTENSION_ERROR = "contains an invalid extension, it was interpreted as "
NO_FILE_ERROR = "there was no provided file name, this is an app error."
EMPTY_FILE_ERROR = "there was no/an empty file, returning 200 OK so device deletes bad file."
DEVICE_IDENTIFIERS_HEADER = "patient_id,MAC,phone_number,device_id,device_os,os_version,product,brand,hardware_id,manufacturer,model,beiwe_version\n"

## manual push notification failures
RESEND_CLICKED = "resend clicked"

DEVICE_CHECKED_IN = "device checked in"
DEVICE_HAS_NO_REGISTERED_TOKEN = "device has no registered token"
PUSH_NOTIFICATIONS_NOT_CONFIGURED = "Push notifications not configured"
MESSAGE_SEND_SUCCESS = "success"  # for historical reasons don't change this without writing a migration
MESSAGE_SEND_FAILED_PREFIX = "message send failed:"
MESSAGE_SEND_FAILED_UNKNOWN = "message send failed: unknown"
SUCCESSFULLY_SENT_NOTIFICATION_PREFIX = "Successfully sent notification to"
BAD_DEVICE_OS = "bad device OS"
BAD_PARTICPANT_OS = "This participant is not properly registered and cannot be sent push notifications until the re-register."
