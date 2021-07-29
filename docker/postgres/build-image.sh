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


mkdir -p release
$(aws ecr get-login --no-include-email --registry-ids ${AWS_ACCOUNT_ID} --region ${AWS_REGION})

docker build -t postgres-maskopy .
docker save postgres-maskopy > postgres-maskopy.tar

mv -f postgres-maskopy.tar release
