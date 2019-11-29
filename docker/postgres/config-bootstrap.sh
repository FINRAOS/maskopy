#!/bin/bash -e
export AWS_DEFAULT_REGION=us-east-1

function log_msg {
#-------------------------------------------------
    LOG_FILE=$1
    LOG_LEVEL=$2
    LOG_MSG=$3
    dt=$(date +"%m/%d/%Y %H:%M:%S")
    echo -e "\n${dt}: ${LOG_LEVEL} - ${LOG_MSG}" | tee -a ${LOG_FILE}
}

function log_vars {
    log_msg "$1" "INFO" "APPLICATION_NAME=${APPLICATION_NAME}"
    log_msg "$1" "INFO" "RDS_INSTANCE_IDENTIFIER=${RDS_INSTANCE_IDENTIFIER}"
    log_msg "$1" "INFO" "OBFUSCATION_SCRIPT_PATH=${OBFUSCATION_SCRIPT_PATH}"
    log_msg "$1" "INFO" "TIMESTAMP=${TIMESTAMP}"
    log_msg "$1" "INFO" "APP_USER=${APP_USER}"
    log_msg "$1" "INFO" "RDS_ENDPOINT=${RDS_ENDPOINT}"
    log_msg "$1" "INFO" "ENDPOINT=${ENDPOINT}"
}

# Update master password of RDS instance.
PASSWORD=$(< /dev/urandom tr -dc A-Za-z0-9 | head -c30)
set -o pipefail

RDS_MASTER_USER=$(aws rds describe-db-instances --db-instance-identifier "${RDS_INSTANCE_IDENTIFIER}" --query 'DBInstances[*].MasterUsername' --output text)
ENDPOINT=$(aws rds describe-db-instances --db-instance-identifier "${RDS_INSTANCE_IDENTIFIER}" --query 'DBInstances[*].Endpoint' --output text)
RDS_ENDPOINT=$(echo ${ENDPOINT} | cut -d ' ' -f 1)
TARGET_PORT=$(echo ${ENDPOINT} | cut -d ' ' -f 3)

aws rds wait db-instance-available --db-instance-identifier "${RDS_INSTANCE_IDENTIFIER}"
aws rds modify-db-instance --db-instance-identifier "${RDS_INSTANCE_IDENTIFIER}" --master-user-password "${PASSWORD}" --apply-immediately
sleep 60
aws rds wait db-instance-available --db-instance-identifier "${RDS_INSTANCE_IDENTIFIER}"

echo  """
#########################################
Running obfuscation commands now.........
#########################################
"""
echo "Downloading Obfuscation scripts from s3://${OBFUSCATION_SCRIPT_PATH} S3 Bucket......."
aws s3 cp "s3://${OBFUSCATION_SCRIPT_PATH}" "/home/${APP_USER}/maskopy" --sse --recursive

touch "/home/${APP_USER}/maskopy/bootstrap.log"
log_vars "/home/${APP_USER}/maskopy/bootstrap.log"

cd "/home/$APP_USER/maskopy"

echo "*:*:*:*:${PASSWORD}" > "/home/$APP_USER/.pgpass"
chmod 600 "/home/$APP_USER/.pgpass"
chown $APP_USER:$APP_USER "/home/$APP_USER/.pgpass"

#  Finding bootstrap.sh to execute
if [ -f bootstrap.sh ]; then
   echo "Found bootstrap.sh file, Executing script now as $APP_USER user...."
   chmod 755 *.sh
   chown -R $APP_USER:$APP_USER /home/$APP_USER/maskopy
   chown -R $APP_USER:$APP_USER /var/log
   chown -R $APP_USER:$APP_USER "/home/${APP_USER}/maskopy/bootstrap.log"
   su -m $APP_USER -c "cd /home/$APP_USER/maskopy; PASSWORD=$PASSWORD bash -e ./bootstrap.sh ${RDS_ENDPOINT} ${TARGET_PORT} ${RDS_MASTER_USER}" | tee -a "/home/${APP_USER}/maskopy/bootstrap.log"
else
   echo "File bootstrap.sh does not exist, Exiting now..."
   exit 1
fi

exit 0
