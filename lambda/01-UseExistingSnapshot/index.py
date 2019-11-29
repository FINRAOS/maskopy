"""
Copyright (c) 2019. Maskopy Contributors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.


This lambda makes a copy of the original snapshot in the source environment.
This copy will then be shared to the destination environment.
An additional copy is created to preserve the state of the original snapshot.
This lambda expects the following inputs:
- ApplicationName
- CostCenter
- DestinationEnv
- RdsSnapshotIdentifier

Optional
- AmiId (required if run mode is set to ecs)
- ExecutionTimestamp
- ObfuscateRunMode
- ObfuscationScriptPath (required if run mode is set to ecs or fargate)
- RdsFinalSnapshotIdentifier
- RdsInstanceType
- RdsOptionGroup
- RdsParameterGroup
"""
import os
import json
import re

import boto3
from botocore.exceptions import ClientError

STS_CLIENT = boto3.client("sts")
CUSTOM_KMS_KEY = os.environ['custom_kms_key']
ASSUME_ROLE_ARN = os.environ['assume_role_arn']

def lambda_handler(event, context):
    """Lambda handler for the zeroth lambda of the Maskopy process.
    Args:
        event (dict): AWS Lambda uses this parameter to pass in event data to the handler.
        context (Context): AWS Lambda provides runtime info and meta data.
    Returns:
        :obj:`dict` of str:str: Return dict with details of snapshot that was created.
    Raises:
        MaskopyResourceNotFoundException: Raised if inputs are not valid.
        Exception: Generic exception raised
            if final snapshot name already exists in destination.
    """

    rds_client_local = boto3.client("rds")
    assume_role_session = create_account_session(
        STS_CLIENT,
        ASSUME_ROLE_ARN,
        context.aws_request_id)
    rds_client = assume_role_session.client('rds')

    # Check if inputs are valid and have valid resources.
    try:
        check_inputs(event)
        check_valid_resources(rds_client_local, rds_client, event)
        print("All input values verified")
    except MaskopyResourceNotFoundException:
        print("One or more of required inputs are missing/invalid. Please check your inputs.")
        raise

    snapshots_created = []
    application_name = event["ApplicationName"]
    cost_center = event["CostCenter"]
    snapshot_identifier = event['RdsSnapshotIdentifier']
    # Get original snapshot_tags to append to cloned snapshot
    snapshot_tags = [
        {'Key': 'ApplicationName', 'Value': 'MASKOPY'},
        {'Key': 'Cost Center', 'Value': cost_center}
    ]

    parameter_group = event.get('RdsParameterGroup')
    if not parameter_group:
        parameter_group = get_parameter_group(rds_client, rds_client_local, snapshot_identifier)

    # If maskopy- snapshot exists, then use already existing snapshot.
    new_snapshot_identifier = (f"MASKOPY-{application_name}-"
                               f"{re.sub('[^A-Za-z0-9-]+', '', snapshot_identifier)}-"
                               f"{context.aws_request_id}")
    new_snapshot = copy_db_snapshot(
        rds_client, snapshot_identifier,
        new_snapshot_identifier,
        snapshot_tags, CUSTOM_KMS_KEY)
    snapshots_created.append({
        'SnapshotName': new_snapshot['DBSnapshotIdentifier'],
        'SnapshotARN': new_snapshot['DBSnapshotArn'],
        'InstanceIdentifier': new_snapshot['DBInstanceIdentifier'],
        'Tags': snapshot_tags,
        'RdsParameterGroup': parameter_group
    })

    return snapshots_created

def check_inputs(step_event):
    """Function to check and validate inputs in step_event dictionary.
       This function does not return anything, but raises MaskopyResourceNotFoundException
       if inputs do not exist or are invalid.
    Args:
        step_event (dict): AWS Lambda uses this parameter to pass in event data to the handler.
    Raises:
        MaskopyResourceNotFoundException: Raised if input is not found or is empty.
    """
    print("Checking step function inputs...")
    # Loop through keys and check if they are not None or empty values in the step_event
    keys = ['ApplicationName', 'CostCenter', 'DestinationEnv', 'RdsSnapshotIdentifier']
    for key in keys:
        if not step_event.get(key):
            raise MaskopyResourceNotFoundException(
                f'{key} is missing. Please check your step function inputs.')

    # Check if RdsFinalSnapshotIdentifier is provided and
    # if so check if it starts with ApplicationName
    if (step_event.get("RdsFinalSnapshotIdentifier") and
            not step_event['RdsFinalSnapshotIdentifier'].startswith(
                step_event['ApplicationName'].lower())):
        raise MaskopyResourceNotFoundException(
            "Given final snapshot name is not valid, must start with lowercase application name.")

    # Check for obfuscation run mode choices: ecs, fargate, and none.
    # The default run mode is fargate.

    if step_event.get('ObfuscateRunMode') == 'ecs':
        # ecs mode requires AmiId and ObfuscationScriptPath inputs
        if not step_event.get('AmiId'):
            raise MaskopyResourceNotFoundException(
                "AmiId is missing. Please check your step function inputs.")
        if not step_event.get('ObfuscationScriptPath'):
            raise MaskopyResourceNotFoundException(
                "ObfuscationScriptPath is missing. Please check your step function inputs.")
    elif (step_event.get('ObfuscateRunMode') == 'none' and
          step_event.get('DestinationEnv') == 'dev'):
        # none mode does not require any additional input checking.
        print("ObfuscateRunMode is none. Running without obfuscation. "
              "Ignoring AmiId, and ObfuscationScriptPath check")
    else:
        # fargate mode requires ObfuscationScriptPath input
        print("ObfuscateRunMode set to fargate.")
        if not step_event.get('ObfuscationScriptPath'):
            raise MaskopyResourceNotFoundException(
                "ObfuscationScriptPath is missing. Please check your step function inputs.")

def check_valid_resources(rds_client_local, rds_client, step_event):
    """Function to check and validate inputs in step_event dictionary.
       This function does not return anything, but raises MaskopyResourceNotFoundException
       if inputs do not exist or are invalid.
    Args:
        rds_client_local (Client): AWS RDS Client object with a local session.
        rds_client (Client): AWS RDS Client object with a source account session.
        step_event (dict): AWS Lambda uses this parameter to pass in event data to the handler.
    Raises:
        MaskopyResourceNotFoundException: Raised if input is not found or is empty.
    """
    # Check if provided RdsSnapshotIdentifier exists in source account.
    # Throw an exception if not found, since we need to copy this snapshot.
    snapshot_response = check_snapshot_exists(rds_client, step_event['RdsSnapshotIdentifier'])
    if not snapshot_response:
        raise MaskopyResourceNotFoundException(
            f"{step_event['RdsSnapshotIdentifier']} does not exist in source account.")

    # Check if provided RdsFinalSnapshotIdentifier already exists in destination environment.
    # If not provided, ignore.
    if (step_event.get('RdsFinalSnapshotIdentifier') and
            check_snapshot_exists(rds_client_local, step_event['RdsFinalSnapshotIdentifier'])):
        raise MaskopyResourceNotFoundException("Final snapshot name already exists.")

    # Check additional resources if obfuscation is required.
    if step_event.get('ObfuscateRunMode') == 'ecs':
        # ecs mode checks for a valid AMI and if ObfuscationScriptPath has a bootstrap script.
        try:
            check_ami_id(step_event['AmiId'])
            check_if_script_path_exists(step_event['ObfuscationScriptPath'])
        except MaskopyResourceNotFoundException:
            print("AMI or script was not found.")
            raise
    elif (step_event.get('ObfuscateRunMode') == 'none' and
          step_event.get('DestinationEnv') == 'dev'):
        print("Skipping check")
    else:
        # fargate mode checks if ObfuscationScriptPath has a bootstrap script.
        print("Setting obfuscation mode to fargate. Checking resources.")
        try:
            check_if_script_path_exists(step_event['ObfuscationScriptPath'])
        except MaskopyResourceNotFoundException:
            print(f"Bootstrap script was not found in {step_event['ObfuscationScriptPath']}.")
            raise

    # Check if the input, RdsParameterGroup, is a valid parameter group.
    if step_event.get('RdsParameterGroup'):
        check_valid_parameter_group(rds_client_local, step_event['RdsParameterGroup'])
    engine = get_db_engine(snapshot_response)
    # If the DB engine is oracle, check if the input, RdsOptionGroup, is a valid option group.
    if "oracle" in engine:
        if not step_event.get('RdsOptionGroup'):
            raise MaskopyResourceNotFoundException(
                "RdsOptionGroup is missing. "
                "It is required if your DBEngine is Oracle based. "
                "Please check your step function inputs.")
        # Check if the input, RdsOptionGroup, is a valid option group.
        check_valid_option_group(rds_client_local, step_event['RdsOptionGroup'])

def check_snapshot_exists(rds_client, snapshot_identifier):
    """Function to check if a snapshot exists.
    Args:
        rds_client (Client): AWS RDS Client object.
        snapshot_identifier (str): The snapshot identifier to check.
    Returns:
        :obj:`dict` of str:str: Snapshot dictionary from AWS boto3 call
            if snapshot exists in session, False otherwise.
    Raises:
        MaskopyThrottlingException: Exception used to catch throttling from AWS.
            Used to implement a back off strategy.
    """
    try:
        print(f'Checking DB snapshot with the following name: {snapshot_identifier}')
        snapshot_response = rds_client.describe_db_snapshots(
            DBSnapshotIdentifier=snapshot_identifier)
        return snapshot_response

    except rds_client.exceptions.DBSnapshotNotFoundFault as err:
        return False
    except ClientError as err:
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        print(f'There was a problem checking the DB snapshot: {err}')
        raise

def check_ami_id(ami_id):
    """Function to validate AMI existence in account.
    Args:
        ami_id (str): AMI identifier to check for existence.
    Raises:
        MaskopyResourceNotFoundException: Raised if AMI is not found.
    """
    print(f'Validating AmiId: {ami_id}')
    ec2_client = boto3.client("ec2")

    try:
        ec2_client.describe_images(ImageIds=[ami_id])
        print("AmiId validated.")
    except ClientError as err:
        print(err)
        raise MaskopyResourceNotFoundException("Please check your AmiId input")

def check_if_script_path_exists(obfuscation_script_path):
    """Function to check bootstrap.sh exists in obfuscation_script_path.
    Args:
        obfuscation_script_path (str): S3 bucket path to check.
    Raises:
        MaskopyResourceException: Raised if S3 bucket cannot be accessed.
        MaskopyResourceNotFoundException: Raised S3 bucket does not exist or
            if path/'boot' prefix is not found in S3 path.
        MaskopyThrottlingException: Exception used to catch throttling from AWS.
            Used to implement a back off strategy.
    """
    print(f'Checking: {obfuscation_script_path}')
    s3_bucket_name = obfuscation_script_path.split('/', 1)[0]
    file_prefix = obfuscation_script_path.split('/', 1)[1] + '/boot'

    s3_client = boto3.client('s3')
    try:
        response = s3_client.list_objects_v2(Bucket=s3_bucket_name, Prefix=file_prefix)
        if not response:
            raise Exception("Please check your ObfuscationScriptPath input.")

        # Check if S3 has any files that have the 'boot' prefix in the S3 path
        if response.get("KeyCount") == 0:
            print("Bootstrap script not found in S3 bucket. "
                  "Please check your ObfuscationScriptPath input.")
            raise MaskopyResourceNotFoundException(
                "Please check your ObfuscationScriptPath input.")

        for obj in response.get("Contents"):
            script_name = obj.get("Key")
            if not script_name:
                print("Please check your ObfuscationScriptPath input")
                raise MaskopyResourceNotFoundException(
                    "Please check your ObfuscationScriptPath input.")
            print(f'Found: {script_name}')

    except ClientError as err:
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        if err.response['Error']['Code'] == "404":
            print("The object does not exist.")
        raise MaskopyResourceException("Please check your ObfuscationScriptPath input.")

def get_parameter_group(rds_client, rds_client_local, snapshot_identifier):
    """Function to get the original parameter group name of snapshot
    Args:
        rds_client (Client): AWS RDS Client object with source session.
        rds_client_local (Client): AWS RDS Client object.
        snapshot_identifier (str): The snapshot identifier.
    Returns:
        str: A parameter group attached to original RDS instance of snapshot.
    Raises:
        MaskopyThrottlingException: Exception used to catch throttling from AWS.
            Used to implement a back off strategy.
    """
    try:
        snapshot = rds_client.describe_db_snapshots(DBSnapshotIdentifier=snapshot_identifier)
        rds_instance = rds_client.describe_db_instances(
            DBInstanceIdentifier=snapshot['DBSnapshots'][0]['DBInstanceIdentifier'])
        parameter_group = rds_instance['DBInstances'][0]['DBParameterGroups'][0]['DBParameterGroupName']
        check_valid_parameter_group(rds_client_local, parameter_group)
        return parameter_group
    except ClientError as err:
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        if err.response['Error']['Code'] == 'DBInstanceNotFound':
            print("Original RDS not available.")
        print(err)
        raise Exception("Parameter group not provided and cannot be extrapolated.")

def get_db_engine(snapshot_response):
    """Function to parse snapshot response from AWS for DB engine.
    Args:
        snapshot_response (str): The snapshot identifier to parse.
    Returns:
        :obj:`str`: The DB engine of the snapshot.
    """
    db_source_snapshot = snapshot_response['DBSnapshots'][0]['DBSnapshotArn']
    print(f'Checking snapshot engine for {db_source_snapshot}')
    return snapshot_response['DBSnapshots'][0]['Engine']

def check_valid_parameter_group(rds_client, parameter_group_name):
    """Function to check for valid parameter group in destination environment.
    Args:
        rds_client (Client): AWS RDS Client object.
        parameter_group_name (str): The parameter group name.
    Raises:
        MaskopyResourceNotFoundException: Exception raised if resource is not found.
        MaskopyThrottlingException: Exception used to catch throttling from AWS.
            Used to implement a back off strategy.
    """
    try:
        if not parameter_group_name:
            raise MaskopyResourceNotFoundException("Please enter a valid RdsParameterGroup.")
        print(f'Validating parameter group: {parameter_group_name}')
        if not rds_client.describe_db_parameter_groups(
                DBParameterGroupName=parameter_group_name):
            raise MaskopyResourceNotFoundException("Please check your RdsParameterGroup.")
        print(f'Validated parameter group: {parameter_group_name}')
    except ClientError as err:
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        print(f'There was a problem checking the parameter group: {err}')
        raise

def check_valid_option_group(rds_client, option_group_name):
    """Function to check for valid option group in destination environment.
    Args:
        rds_client (Client): AWS RDS Client object.
        option_group_name (str): The option group name.
    Returns:
        :obj:`str`: The DB engine of the snapshot.
    Raises:
        MaskopyResourceNotFoundException: Exception raised if resource is not found.
        MaskopyThrottlingException: Exception used to catch throttling from AWS.
            Used to implement a back off strategy.
    """
    try:
        print(f'Validating option group: {option_group_name}')
        if not rds_client.describe_option_groups(
                OptionGroupName=option_group_name):
            raise MaskopyResourceNotFoundException("Please check your RdsOptionGroup.")
        print(f'Validated option group successfully.')
    except ClientError as err:
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        print(f'There was a problem checking the option group: {err}')
        raise

def copy_db_snapshot(rds_client, source_db_snapshot_identifier,
                     destination_db_snapshot_identifier, snapshot_tags, kms_key=None):
    """Function to create a copy of a rds snapshot, copying tags by default.
    Args:
        rds_client (Client): AWS RDS Client object.
        source_db_snapshot_identifier (str): The source snapshot identifier.
        destination_db_snapshot_identifier (str): The destination snapshot identifier.
        snapshot_tags (dict): A dict of tags to be added to snapshot
        kms_key (str, optional): KMS Key to encrypt snapshot.
    Returns:
        :dict`: Returns a dict of the created snapshot.
    Raises:
        MaskopyResourceException: Raised if resource cannot be accessed.
    """
    copy_db_snapshot_parameters = {
        'SourceDBSnapshotIdentifier': source_db_snapshot_identifier,
        'TargetDBSnapshotIdentifier': destination_db_snapshot_identifier,
        'Tags': snapshot_tags
    }
    if kms_key:
        copy_db_snapshot_parameters['KmsKeyId'] = kms_key
    try:
        print("Copying DB snapshot with the following parameters: ")
        print(json.dumps(copy_db_snapshot_parameters))

        destination_snapshot_response = check_snapshot_exists(
            rds_client,
            destination_db_snapshot_identifier)
        if not destination_snapshot_response:
            copy_db_snapshot_response = rds_client.copy_db_snapshot(
                **copy_db_snapshot_parameters)
            print(f"Successfully copied DB snapshot: {destination_db_snapshot_identifier}")
            return copy_db_snapshot_response['DBSnapshot']

        print(f'{destination_db_snapshot_identifier} already exists. Using existing snapshot.')
        return destination_snapshot_response['DBSnapshots'][0]

    except ClientError as err:
        raise MaskopyResourceException("Could not copy snapshot: %s" % err)


def create_account_session(sts_client, role_arn, request_id):
    """Function to create and assume account role.
    Args:
        sts_client (Client): AWS STS Client object.
        role_arn (str): The arn of the role to assume a session.
        request_id (str): UUID for session to uniquely identify session name.
    Returns:
        :obj:`boto3.session.Session`:
            A session of the role to be used.
    """
    sts_response = sts_client.assume_role(
        RoleArn=role_arn,
        RoleSessionName=request_id
    )

    return boto3.session.Session(
        aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
        aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
        aws_session_token=sts_response['Credentials']['SessionToken']
    )

class MaskopyThrottlingException(Exception):
    """Exception raised when AWS request returns a Throttling exception.
    """

class MaskopyResourceNotFoundException(Exception):
    """Exception raised when IAM role or user is not able to access the
    resource since the resource does not exist.
    """

class MaskopyResourceException(Exception):
    """Exception raised when IAM role or user is not able to access the
    resource.
    """
