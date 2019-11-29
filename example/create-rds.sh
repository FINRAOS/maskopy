#!/bin/bash

export AWS_DEFAULT_REGION="$(aws configure list | grep region | awk '{print $2}')"

export INSTANCE_IDENTIFIER="maskopy-test-db"
export INSTANCE_STORAGE=20
export INSTANCE_CLASS="db.t2.small"
export MASTER_USER="maskopymaster"
export DB_NAME="MASKOPY"
export DB_SUBNET="db-subnet-g1"
export SG_LIST=YOUR_SG_LIST


PASSWORD=$(< /dev/urandom tr -dc A-Za-z0-9 | head -c30)

aws rds create-db-instance \
    --db-instance-identifier ${INSTANCE_IDENTIFIER} \
    --allocated-storage ${INSTANCE_STORAGE} \
    --db-instance-class ${INSTANCE_CLASS} \
    --engine postgres \
	--engine-version 11.1 \
	--port 5432 \
	--db-name ${DB_NAME} \
    --master-username ${MASTER_USER} \
    --master-user-password ${PASSWORD} \
	--db-subnet-group-name ${DB_SUBNET} \
	--vpc-security-group-ids ${SG_LIST} \
	--no-publicly-accessible \
	--tags Key=ApplicationName,Value=MASKOPY \
         Key="Cost Center",Value=YOUR_COSTCENTER
		 
if [ $? -ne 0 ]; then
	echo "Failed to Create RDS instance ${INSTANCE_IDENTIFIER}"
	exit 1;
fi

sleep 60
echo "INFO:!! Waiting for the RDS Instance to be available."

aws rds wait db-instance-available --db-instance-identifier "${INSTANCE_IDENTIFIER}"
if [ $? -eq 255 ];then
    echo "WARN:!!	RDS wait exceeded default wait time.. Waiting one more time"
    aws rds wait db-instance-available --db-instance-identifier "${INSTANCE_IDENTIFIER}"
fi
