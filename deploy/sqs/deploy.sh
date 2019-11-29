#!/bin/bash

usage () {
    cat <<USAGE

    $0 -n <queue name> -r <region>
    ex: $0 -n maskopy-queue -r us-east-1
    -n  AWS SQS queue name
    -r  AWS region.
USAGE

    exit 0
}

[ $# -lt 3 ] && { usage; }

while getopts ':n:r:' flag; do
  case "${flag}" in
    n) export SQS_NAME="${OPTARG}" ;;
    r) export AWS_REGION="${OPTARG}" ;;
    *) usage
       exit 1 ;;
  esac
done


#Checking if queue already exists or not. 
aws sqs get-queue-url --queue-name ${SQS_NAME} --region ${AWS_REGION}
if [[ $? -ne 0 ]]; then
  echo "SQS Queue doesn't exists, creating new one"
else
  echo "SQS Queue already exists, skipping creation"
  exit 0
fi

aws sqs create-queue --queue-name ${SQS_NAME} --region ${AWS_REGION}