#!/bin/bash
set -e

CUR_DIR=$(pwd)
cd $CUR_DIR/lambda
bash ./deploy.sh -a "${CROSS_ACCOUNT_ROLE}" \
    -c "${COST_CENTER}" \
    -d "${STAGING_KEY}" \
	-e "${FARGATE_TASK_ROLE}" \
	-f "${DEFAULT_DOCKER_IMAGE}" \
    -g "${LAMBDA_SECURITY_GROUP}" \
    -i "${DESTINATION_ACCOUNT_ID}" \
    -k "${ORIGINAL_KMS_KEY}" \
    -l "${LAMBDA_SUBNET_LIST}" \
    -n "${LAMBDA_ROLE}" \
    -r "${AWS_REGION}" \
    -s "${LAMBDA_BUCKET_LOCATION}" \
    -t "${RDS_SUBNET_GROUP}" \
    -y "${RDS_SECURITY_GROUP}"

cd $CUR_DIR/stepfunction
bash ./deploy.sh -a "${STAGING_ACCOUNT_ID}" \
    -g "${FARGATE_SECURITY_GROUP}" \
    -n "${FARGATE_SUBNET0}" -n "${FARGATE_SUBNET1}" \
    -r "${AWS_REGION}" \
    -s "${SQS_NAME}" \
    -t "${LAMBDA_ROLE}"

