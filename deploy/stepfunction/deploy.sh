#!/bin/bash
set -e

usage () {
    cat <<USAGE

    $0 -a <staging account> -g <sg> -n <subnet> -r <region> -s <queue_name> -t <role>
    ex: $0 -a 012345678910 -g sg-123 -g sg-456 -n subnet-123 -n subnet-456 -r us-east-1 -s SQS_NAME -t MASKOPY_stepfunction_role

    -a  AWS staging account number.
    -g  AWS security groups to attach to fargate cluster.
    -n  AWS subnets to attach to fargate cluster.
    -r  AWS region.
    -s  AWS SQS queue.
    -t  AWS step function role name.
USAGE

    exit 0
}
function join_by { local IFS="$1"; shift; echo "$*"; }

[ $# -lt 12 ] && { usage; }

while getopts ':a:g:n:r:s:t:' flag; do
  case "${flag}" in
    a) export ACCOUNT="${OPTARG}" ;;
    g) SECURITY_GROUPS+=("\"${OPTARG}\"") ;;
    n) SUBNET+=("\"${OPTARG}\"") ;;
    r) export AWS_REGION="${OPTARG}" ;;
    s) export SQS_NAME="${OPTARG}" ;;
    t) export ROLE_NAME="${OPTARG}" ;;
    *) usage
       exit 1 ;;
  esac
done
CF_STACK_NAME=MASKOPY-stepfunction


sed -i -e "s/REGION/${AWS_REGION}/g" ../../stepfunction/state_machine.json
sed -i -e "s/ACCOUNT/${ACCOUNT}/g" ../../stepfunction/state_machine.json
sed -i -e "s/SQS_NAME/${SQS_NAME}/g" ../../stepfunction/state_machine.json
sed -i -e "s/AWS_SECURITY_GROUPS/$(join_by , "${SECURITY_GROUPS[@]}")/g" ../../stepfunction/state_machine.json
sed -i -e "s/AWS_SUBNETS/$(join_by , "${SUBNET[@]}")/g" ../../stepfunction/state_machine.json

# Replacing State Mechine Definition as string in stepfunction-cf.json
python replace_cfn.py ../../stepfunction/state_machine.json stepfunction-cf.json

aws cloudformation create-stack --stack-name ${CF_STACK_NAME} --template-body file://stepfunction-cf.json \
    --parameters ParameterKey=StepfunctionRoleName,ParameterValue="${ROLE_NAME}" --region "${AWS_REGION}"
if [ $? -ne 0 ]; then
    echo "Failed to Create Cloudformation Stack: ${CF_STACK_NAME}"
    exit 1;
fi

sleep 10

aws cloudformation wait stack-create-complete --stack-name ${CF_STACK_NAME} --region "${AWS_REGION}"
if [ $? -ne 0 ]; then
    echo "Failed to wait for Cloudformation Stack to complete: ${CF_STACK_NAME}"
    exit 1;
fi