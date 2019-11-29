#!/bin/bash
set -e

usage () {
    cat <<USAGE

    $0 -a <staging account id> -r <region>
    ex: $0 -a 012345678910 -r us-east-1

    -a  Staging account ID to host docker image.
    -r  AWS region.
USAGE

    exit 0
}

[ $# -lt 4 ] && { usage; }

while getopts ':a:r:' flag; do
  case "${flag}" in
    a) export AWS_ACCOUNT_ID="${OPTARG}" ;;
    r) export AWS_REGION="${OPTARG}" ;;
    *) usage
       exit 1 ;;
  esac
done

IMAGE_NAME=${AWS_ACCOUNT_ID}.dkr.ecr.us-east-1.amazonaws.com/maskopy
IMAGE_SUFFIX=$(date +%Y%m%d%H%M%S)
cd release

$(aws ecr get-login --no-include-email --region ${AWS_REGION} --registry-ids ${AWS_ACCOUNT_ID})

# Creating ECR repository if doesn't exists

if ! aws ecr describe-repositories --repository-names maskopy; then
	echo "ECR repository doesn't exists, creating new one"
	aws ecr create-repository --repository-name maskopy
else
	echo "ECR repository exists, skipping creation"
fi

docker load -i postgres-maskopy.tar
docker images
docker tag postgres-maskopy:latest ${IMAGE_NAME}:${IMAGE_SUFFIX}
docker push ${IMAGE_NAME}:${IMAGE_SUFFIX}
docker tag postgres-maskopy:latest ${IMAGE_NAME}:latest
docker push ${IMAGE_NAME}:latest
