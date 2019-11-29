#!/bin/bash
set -e

usage () {
    cat <<USAGE

    $0 -r <region>
    ex: $0 -r us-east-1

   	-r  AWS region.
USAGE

    exit 0
}

[ $# -lt 2 ] && { usage; }

while getopts ':r:' flag; do
  case "${flag}" in
    r) export AWS_REGION="${OPTARG}" ;;
    *) usage
       exit 1 ;;
  esac
done

export ECR_NAME=maskopy

#Check if ECR repo exist.
if ! aws ecr describe-repositories --repository-names ${ECR_NAME} --region ${AWS_REGION}; then
	echo "ECR repository doesn't exists, creating new one"
else
	echo "ECR repository already exists, skipping creation"
	exit 0
fi

aws ecr create-repository --repository-name ${ECR_NAME}
