#!/bin/bash -x

#Check inputs
echo "Validating mandatory inputs"

if [[ -z ${APPLICATION_NAME} || -z ${DESTINATION_ENV} || -z ${RDS_SNAPSHOT_IDENTIFIER} ]]; then
    echo "!! ERROR !! One of the required inputs is missing. Please check."
    exit 1
else
  echo "APPLICATION_NAME, DESTINATION_ENV, RDS_SNAPSHOT_IDENTIFIER inputs available, proceeding "

fi

BUILD_TIMESTAMP=$(date +%Y%m%d%H%M%S)
EXEC_NAME=${APPLICATION_NAME}-${BUILD_TIMESTAMP}
URL=$(python -c "import boto3; print(boto3.client('sts').generate_presigned_url('get_caller_identity'))")

if [[ -z ${URL} ]]; then
    echo "URL generation failed, stopping!!"
    exit 1
fi

echo "Executing stateMachine: ${STEP_FN_ARN}"
executionArn=$(aws stepfunctions start-execution --query 'executionArn' --cli-input-json ' { "stateMachineArn": "'${STEP_FN_ARN}'", "name": "'${EXEC_NAME}'", "input": "{\"ApplicationName\": \"'${APPLICATION_NAME}'\",\"CostCenter\": \"'${COST_CENTER}'\",\"DestinationEnv\": \"'${DESTINATION_ENV}'\",\"RdsSnapshotIdentifier\":\"'${RDS_SNAPSHOT_IDENTIFIER}'\",\"RdsOptionGroup\": \"'${RDS_OPTION_GROUP}'\",\"RdsParameterGroup\":\"'${RDS_PARAMETER_GROUP}'\",\"ObfuscationScriptPath\":\"'${OBFUSCATION_SCRIPT_PATH}'\",\"PresignedUrl\":\"'${URL}'\" }" } ' | tr -d '"')
if [ "$?" -ne 0 ]
then
    echo "Deployment failed!"
    exit 1
fi

echo -e """
\n\n\n\n\n
------------------------------------------------------
READ ME!!!!!!!!IMPORTANT!!!!!!!!!
------------------------------------------------------
Link to stateMachine: https://console.aws.amazon.com/states/home?region=${AWS_DEFAULT_REGION}#/statemachines/view/${STEP_FN_ARN}
Link to execution: https://console.aws.amazon.com/states/home?region=${AWS_DEFAULT_REGION}#/executions/details/${executionArn}
\n\n\n\n\n
"""
