#!/bin/bash
set -e

usage () {
    cat <<USAGE
    Create KMS key.
    $0 -l <lambda role> -r <region> -s <source account id> -t <staging account id> 
    ex: $0 -l LAMBDA_test_role -r us-east-1 -s 109876543210 -t 012345678910 
    -l  lambda role name to allow key usage.
    -r  AWS region.
    -s  source account id.
    -t  staging account id.
USAGE

    exit 0
}

[ $# -lt 8 ] && { usage; }

while getopts ':l:r:s:t:' flag; do
  case "${flag}" in
    l) export LAMBDA_ROLE_NAME="${OPTARG}" ;;
    r) export AWS_REGION="${OPTARG}" ;;
    s) export SOURCE_ACCOUNT_ID="${OPTARG}" ;;
    t) export STAGING_ACCOUNT_ID="${OPTARG}" ;;
    *) usage
       exit 1 ;;
  esac
done

sed -i "s/STAGE_ACCOUNT_ID/${STAGING_ACCOUNT_ID}/" policy.json
sed -i "s/SOURCE_ACCOUNT_ID/${SOURCE_ACCOUNT_ID}/" policy.json
sed -i "s/LAMBDA_MASKOPY/${LAMBDA_ROLE_NAME}/" policy.json

# Create kms key
KEY_ID=$(aws kms create-key --policy file://policy.json --query 'KeyMetadata.KeyId' --region ${AWS_REGION} --output text)
aws kms create-alias --alias-name alias/MaskopyKey --target-key-id "${KEY_ID}"
