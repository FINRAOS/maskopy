#!/bin/bash
set -e

usage () {
    cat <<USAGE

    $0 -a <assume role arn> -c <cost center> -d <destination key arn> -e <ecs service role>
    -f <default image> -g <lambda security groups> -i <destination account id> 
    -k <master key arn> -l <lambda subnet list> -n <lambda role name> -r <region> 
    -s <s3_location> -t <rds subnet group name> -y <rds security group list>
    ex: $0 -a arn::assumed_role \
    -c abc123 \
    -d arn:kms:dev_key \
    -e ECS_MASKOPY \
    -f 012345678910.dkr.ecr.us-east-1.amazonaws.com/maskopy:latest
    -g sg-123,sg-456 \
    -i 012345678910 \
    -k arn:kms:master_key \
    -l subnet-123,subnet-456 \
    -n MASKOPY_lambda \
    -r us-east-1 \
    -s staging_s3_bucket/MASKOPY/ \
    -t dbsubnetgroup1 \
    -y sg-123,sg-456

    -a  Role ARN to assume.
    -c  Cost center
    -d  Key ARN in destination account.
    -e  ECS service role.
    -f  Default image used for fargate task.
    -g  Security groups to be added to lambdas.
    -i  Account ID of destination account.
    -k  Key ARN for source RDS snapshot.
    -l  Subnet list to be added to lambdas.
    -r  AWS region.
    -s  S3 bucket to stage lambda artifacts.
    -t  Subnet group name to be added to RDS instance.
    -y  Security group to be added to RDS instance.
USAGE

    exit 0
}

[ -z $1 ] && { usage; }

while getopts ':a:c:d:e:f:g:i:k:l:n:r:s:t:y:' flag; do
  case "${flag}" in
    a) export ASSUME_ROLE_ARN="${OPTARG}" ;;
    c) export COST_CENTER="${OPTARG}" ;;
    d) export DESTINATION_ACCOUNT_KEY_ARN="${OPTARG}" ;;
    e) export ECS_SERVICE_ROLE="${OPTARG}" ;;
    f) export DEFAULT_IMAGE="${OPTARG}" ;;
    g) export LAMBDA_SECURITY_GROUP="${OPTARG}" ;;
    i) export DESTINATION_ACCOUNT_ID="${OPTARG}" ;;
    k) export MASTER_KEY="${OPTARG}" ;;
    l) export LAMBDA_SUBNET="${OPTARG}" ;;
    n) export LAMBDA_ROLE_NAME="${OPTARG}" ;;
    r) export AWS_REGION="${OPTARG}" ;;
    s) export S3_BUCKET="${OPTARG}" ;;
    t) export RDS_SUBNET_NAME="${OPTARG}" ;;
    y) export RDS_SECURITY_GROUP="${OPTARG}" ;;
    *) usage
       exit 1 ;;
  esac
done

# Packaging the lambda code.
PWD=$(pwd)
LAMBDA_DIRECTORY="$PWD/../../lambda"
RELEASE_DIRECTORY="$PWD/release/"
mkdir -p "${RELEASE_DIRECTORY}"

shopt -s dotglob
find ${LAMBDA_DIRECTORY}/* -prune -type d | while IFS= read -r d; do 
    echo "folderName: $d"
    lambdaName=$(basename "$d")
    echo "lambdaName: $d"
    cd "${LAMBDA_DIRECTORY}/${lambdaName}"
	chmod 644 index.py
    python3 -m pip install -r "${LAMBDA_DIRECTORY}/requirements.txt" -t .
    zip -r "${lambdaName}.zip" *
    cp *.zip "${RELEASE_DIRECTORY}"
done

export CF_STACK_NAME=MASKOPY-lambda
# Deploy the lambda code to S3.
aws s3 cp "${RELEASE_DIRECTORY}" "s3://${S3_BUCKET}" --recursive

# Create CloudFormation for lambda.
cd "${PWD}"
aws cloudformation create-stack --stack-name ${CF_STACK_NAME} \
    --template-body file://lambdas-cf.json \
    --parameters \
    ParameterKey=assumeRoleArn,ParameterValue="${ASSUME_ROLE_ARN}" \
    ParameterKey=costCenter,ParameterValue="${COST_CENTER}" \
    ParameterKey=defaultImage,ParameterValue="${DEFAULT_IMAGE}" \
    ParameterKey=destinationAccountKeyArn,ParameterValue="${DESTINATION_ACCOUNT_KEY_ARN}" \
    ParameterKey=destinationAccountId,ParameterValue="${DESTINATION_ACCOUNT_ID}" \
    ParameterKey=ecsServiceRole,ParameterValue="${ECS_SERVICE_ROLE}" \
    ParameterKey=lambdaRoleName,ParameterValue="${LAMBDA_ROLE_NAME}" \
    ParameterKey=lambdaSubnetList,ParameterValue="\"${LAMBDA_SUBNET}\"" \
    ParameterKey=lambdaSecurityGroupList,ParameterValue="${LAMBDA_SECURITY_GROUP}" \
    ParameterKey=masterAccessKeyArn,ParameterValue="${MASTER_KEY}" \
    ParameterKey=rdsSecurityGroupList,ParameterValue="${RDS_SECURITY_GROUP}" \
    ParameterKey=rdsSubnetGroupName,ParameterValue="${RDS_SUBNET_NAME}" \
    ParameterKey=s3Bucket,ParameterValue="${S3_BUCKET%%'/'*}" \
    ParameterKey=s3Prefix,ParameterValue="${S3_BUCKET#*'/'}" \
    --region "${AWS_REGION}"
if [ $? -ne 0 ]; then
    echo "Failed to Create Cloudformation Stack: ${CF_STACK_NAME}"
    exit 1;
fi

sleep 10

aws cloudformation wait stack-create-complete --stack-name ${CF_STACK_NAME}
if [ $? -ne 0 ]; then
    echo "Failed to wait for Cloudformation Stack to complete: ${CF_STACK_NAME}"
    exit 1;
fi