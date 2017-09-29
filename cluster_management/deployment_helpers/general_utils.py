# Do not import from other utils files here

import logging
import os
import sys
from time import sleep

import botocore.exceptions as botoexceptions
from fabric.exceptions import NetworkError

# Folder and file names
# Remote
REMOTE_USER = 'ubuntu'
REMOTE_HOME_DIR = os.path.join('/home', REMOTE_USER)
LOG_FILE = os.path.join(REMOTE_HOME_DIR, 'server_setup.log')
OS_ENVIRON_SETTING_REMOTE_FILE = os.path.join(REMOTE_HOME_DIR,
                                              'beiwe-backend/config/remote_db_env.py')

# Local
CLUSTER_MANAGEMENT_FOLDER = os.path.abspath(__file__).rsplit('/', 2)[0]
PUSHED_FILES_FOLDER = os.path.join(CLUSTER_MANAGEMENT_FOLDER, 'pushed_files')
USER_SPECIFIC_CONFIG_FOLDER = os.path.join(CLUSTER_MANAGEMENT_FOLDER, 'my_cluster_configuration')
AWS_PEM_FILE = os.path.join(USER_SPECIFIC_CONFIG_FOLDER, 'aws_deployment_key.pem')
AWS_CREDENTIALS_FILE = os.path.join(USER_SPECIFIC_CONFIG_FOLDER, 'aws_credentials.json')
OS_ENVIRON_SETTING_LOCAL_FILE = os.path.join(CLUSTER_MANAGEMENT_FOLDER, 'remote_db_env.py')


# Utilities to install
# AJK TODO document what each of these is for
APT_GET_INSTALLS = [
    'ack-grep',  # Search within files
    'htop',
    'libbz2-dev',
    'libreadline-gplv2-dev',
    'libsqlite3-dev',
    'libssl-dev',
    # AJK TODO do I need this? github says I do
    # 'mailutils',  # Necessary for cronutils
    'moreutils',  # Necessary for cronutils
    'nload',
    'rabbitmq-server',  # Queue tasks to run using celery
    'sendmail',  # Necessary for cronutils
    'silversearcher-ag',  # Search within files
]

log = logging.getLogger(CLUSTER_MANAGEMENT_FOLDER)


def retry(func, *args, **kwargs):
    while True:
        print(".")
        sys.stdout.flush()
        try:
            return func(*args, **kwargs)
        except (NetworkError, botoexceptions.ClientError, botoexceptions.WaiterError) as e:
            log.debug("retrying due to %s" % e)
            sleep(3)
