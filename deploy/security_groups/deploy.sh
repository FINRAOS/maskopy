#!/bin/bash
set -e

usage () {
    cat <<USAGE

    $0 -i <cidr range> -r <region> -v <vpc id>
    ex: $0 -i 10.1.1.1/24 -r us-east-1 -v vpc-123456

    -i  CIDR range of ip for instance security group.
    -r  AWS region.
    -v  VPC id to place security group.
USAGE

    exit 0
}

[ $# -lt 6 ] && { usage; }

while getopts ':i:r:v:' flag; do
  case "${flag}" in
    i) export CIDR_RANGE="${OPTARG}" ;;
    r) export AWS_REGION="${OPTARG}" ;;
    v) export VPC_ID="${OPTARG}" ;;
    *) usage
       exit 1 ;;
  esac
done

export CF_STACK_NAME=MASKOPY-security-group

aws cloudformation delete-stack --stack-name "${CF_STACK_NAME}" --region "${AWS_REGION}"
aws cloudformation wait stack-delete-complete --stack-name "${CF_STACK_NAME}"
aws cloudformation create-stack --stack-name "${CF_STACK_NAME}" --template-body file://sg-cf.json \
    --parameters ParameterKey=vpcID,ParameterValue="${VPC_ID}" ParameterKey=cidr,ParameterValue="${CIDR_RANGE}" --region "${AWS_REGION}"
if [ $? -ne 0 ]; then
    echo "Failed to Create Cloudformation Stack: ${CF_STACK_NAME}"
    exit 1;
fi

sleep 10

aws cloudformation wait stack-create-complete --stack-name "${CF_STACK_NAME}"
if [ $? -ne 0 ]; then
    echo "Failed to wait for Cloudformation Stack to complete: ${CF_STACK_NAME}"
    exit 1;
fi