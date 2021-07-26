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
- BuildTimestamp
- CostCenter
- DestinationEnv
- RdsSnapshotIdentifier

Optional
- AmiId (required if run mode is set to ecs)
- DbName
- ObfuscationScriptPath (required if run mode is set to ecs or fargate)
- RdsFinalSnapshotIdentifier
- RdsInstanceType
- RdsOptionGroup
- RdsParameterGroup
- SqlScriptList
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
    """Lambda handler for the first lambda of the Maskopy process.
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
    return {"firstSnapshotIdentifier": event.get("RdsSnapshotIdentifier")}

def check_inputs(step_event):
    """Function to check and validation inputs in step_event dictionary.
       This function does not return anything, but raises MaskopyResourceNotFoundException
       if inputs do not exist or are invalid.
    Args:
        step_event (dict): AWS Lambda uses this parameter to pass in event data to the handler.
    Raises:
        MaskopyResourceNotFoundException: Raised if input is not found or is empty.
    """
    print("Checking step function inputs...")
    # Loop through keys and check if they are not None or empty values in the step_event
    keys = ['ApplicationName', 'CostCenter', 'DestinationEnv']
    for key in keys:
        if not step_event.get(key):
            raise MaskopyResourceNotFoundException(
                f'{key} is missing. Please check your step function inputs.')
    if not 'RdsSnapshotIdentifier' in step_event and not 'RdsInstanceIdentifier' in step_event:
        raise MaskopyResourceNotFoundException(
            'Both snapshot identifier and rds missing')
    # Check if RdsFinalSnapshotIdentifier is provided and
    # if so check if it starts with ApplicationName
    if (step_event.get("RdsFinalSnapshotIdentifier") and
            not step_event['RdsFinalSnapshotIdentifier'].startswith(
                step_event['ApplicationName'].lower())):
        raise MaskopyResourceNotFoundException(
            "Given final snapshot name is not valid, must start with lowercase ApplicationName.")

    # Check for obfuscation run mode choices: ecs, fargate, and none.
    # The default run mode is fargate.

    print("ObfuscateRunMode set to fargate.")
    if not step_event.get('ObfuscationScriptPath'):
        raise MaskopyResourceNotFoundException(
            "ObfuscationScriptPath is missing. Please check your step function inputs.")

def check_valid_resources(rds_client_local, rds_client, step_event):
    """Function to check and validation inputs in step_event dictionary.
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

    engine= step_event['Engine']['Type']
    snapshot_response = check_snapshot_exists(rds_client, step_event['RdsSnapshotIdentifier'],engine)
    if not snapshot_response:
        raise MaskopyResourceNotFoundException(
            f"{step_event['RdsSnapshotIdentifier']} does not exist in source account.")

    # Check if provided RdsFinalSnapshotIdentifier already exists in destination environment.
    # If not provided, ignore.
    if not step_event.get('RdsSnapshotIdentifier'):
        if not step_event.get('RdsInstanceIdentifier'):
            raise Exception("RdsSnapshotIdentifier is missing. Please check your step function inputs.")
        else:
            step_event['RdsSnapshotIdentifier']=get_snapshot_from_rds(rds_client, step_event.get('RdsInstanceIdentifier'),engine)
    if (step_event.get('RdsFinalSnapshotIdentifier') and
            check_snapshot_exists(rds_client_local,step_event['RdsFinalSnapshotIdentifier'],engine)):
        raise MaskopyResourceNotFoundException("Final snapshot name already exists.")


    # Check if the input, RdsParameterGroup, is a valid parameter group.
    if step_event.get('RdsParameterGroup'):
        check_valid_parameter_group(rds_client_local, step_event['RdsParameterGroup'],engine)
    # If the DB engine is oracle, check if the input, RdsOptionGroup, is a valid option group.
    if "oracle" in engine:
        if not step_event.get('RdsOptionGroup'):
            raise MaskopyResourceNotFoundException(
                "RdsOptionGroup is missing. "
                "It is required if your DBEngine is Oracle based. "
                "Please check your step function inputs.")
        # Check if the input, RdsOptionGroup, is a valid option group.
        check_valid_option_group(rds_client_local, step_event['RdsOptionGroup'])

    if "postgres" in engine:
        if not step_event.get('SqlScriptList'):
            raise MaskopyResourceNotFoundException(
                "SqlScriptList is missing. "
                "It is required if your DBEngine is Postgres based. "
                "Please check your step function inputs.")
        if not step_event.get('DbName'):
            raise MaskopyResourceNotFoundException(
                "DbName is missing. "
                "It is required if your DBEngine is Postgres based. "
                "Please check your step function inputs.")

    # fargate mode checks if ObfuscationScriptPath has a bootstrap script.
    print("Setting obfuscation mode to fargate. Checking resources.")
    try:
        check_if_script_path_exists(step_event.get('ObfuscationScriptPath'), engine, step_event.get('SqlScriptList'))
    except MaskopyResourceNotFoundException:
        print(f"Bootstrap script was not found in {step_event.get('ObfuscationScriptPath')}.")
        raise




def check_snapshot_exists(rds_client, snapshot_identifier, rds_type):

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

    if "aurora" in rds_type:

        return check_snapshot_exists_cluster(rds_client, snapshot_identifier)
    else:
        return check_snapshot_exists_instance(rds_client, snapshot_identifier)


def check_snapshot_exists_cluster(rds_client, snapshot_identifier):
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
        print(f'Checking DB cluster snapshot with the following name: {snapshot_identifier}')
        snapshot_response = rds_client.describe_db_cluster_snapshots(
            DBClusterSnapshotIdentifier=snapshot_identifier)
        return snapshot_response

    except rds_client.exceptions.DBSnapshotNotFoundFault as err:
        return False
    except ClientError as err:
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        print(f'There was a problem checking the DB cluster snapshot: {err}')
        #raise
        return False #CHECK IF VALID OUTPUT

def check_snapshot_exists_instance(rds_client, snapshot_identifier):
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

# Legacy method. No longer used since EC2 tasks are no longer used.
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
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        print(err)
        raise MaskopyResourceNotFoundException("Please check your 'AmiId' input.")

def check_if_script_path_exists(obfuscation_script_path, engine, sql_script_list=None):
    """Function to check bootstrap.sh exists in obfuscation_script_path.
    Args:
        obfuscation_script_path (str): S3 bucket path to check.
        engine (str): The engine of the RDS instance.
        sql_script_list (str, optional): List of SQL files to check.
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
        if "oracle" in engine:
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
        elif "postgres" in engine:
            for file in sql_script_list.split(','):

                print(f"Checking: {obfuscation_script_path.split('/', 1)[1]}/{file}")
                if not file.endswith(".sql"):
                    raise Exception(f"Please check your sql_script_list input. "
                                    f"{file} does not seem to be an sql file.")
                file_prefix = f"{obfuscation_script_path.split('/', 1)[1]}/{file}"
                response = s3_client.list_objects_v2(Bucket=s3_bucket_name, Prefix=file_prefix)
                if not response:
                    raise Exception(
                        "Please check your ObfuscationScriptPath and SqlScriptList input.")

                # Check if S3 has the files in SqlScriptList
                if response.get("KeyCount") == 0:
                    print(f"{file} not found in S3 bucket.")
                    raise MaskopyResourceNotFoundException(
                        "Please check your ObfuscationScriptPath and SqlScriptList input.")

                for obj in response.get("Contents"):
                    script_name = obj.get("Key")
                    if not script_name:
                        print("Please check your ObfuscationScriptPath and SqlScriptList input")
                        raise MaskopyResourceNotFoundException(
                            "Please check your ObfuscationScriptPath and SqlScriptList input.")
                    print(f'Found: {script_name}')
        else:
            print(f"Please check your engine type. {engine} is not supported.")
            raise MaskopyResourceException(f"{engine} is not supported.")

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
        parameter_group = (rds_instance['DBInstances'][0]
        ['DBParameterGroups'][0]
        ['DBParameterGroupName'])
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


def check_valid_parameter_group(rds_client, parameter_group_name, engine):

    """Function to check for valid parameter group in destination environment.
    Args:
        rds_client (Client): AWS RDS Client object.
        parameter_group_name (str): The parameter group name.
    Raises:
        MaskopyResourceNotFoundException: Exception raised if resource is not found.
        MaskopyThrottlingException: Exception used to catch throttling from AWS.
            Used to implement a back off strategy.
    """

    if 'aurora' in engine:
        return check_valid_parameter_group_cluster(rds_client, parameter_group_name)
    else:
        return check_valid_parameter_group_instance(rds_client, parameter_group_name)



def check_valid_parameter_group_instance(rds_client, parameter_group_name):

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

def check_valid_parameter_group_cluster(rds_client, parameter_group_name):

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
        if not rds_client.describe_db_cluster_parameter_groups(
                DBClusterParameterGroupName=parameter_group_name):
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

def get_snapshot_from_rds(rds_client, rds_identifier, engine):
    """Return snapshot to use based off latest snapshot from an RDS instance"""
    if 'aurora' in engine:
        cluster_snapshots = get_db_snapshots_cluster(rds_client, rds_identifier)
        return get_latest_snapshot_identifier(cluster_snapshots,engine)

    else:
        instance_snapshots = get_db_snapshots_instance(rds_client, rds_identifier)
        return get_latest_snapshot_identifier(instance_snapshots,engine)


def get_db_snapshots_cluster(rds_client, cluster_identifier=None, snapshot_type=None, snapshot_identifier=None):
    """Return list of snapshots from an RDS cluster"""

    describe_db_snapshot_params = {}
    if cluster_identifier:
        describe_db_snapshot_params['DBClusterIdentifier'] = cluster_identifier
    if snapshot_type:
        describe_db_snapshot_params['snapshot_type'] = snapshot_type
    if snapshot_identifier:
        describe_db_snapshot_params['DBSnapshotIdentifier'] = snapshot_identifier
    try:
        print('Getting DB snapshots with the following parameters: ')
        print(json.dumps(describe_db_snapshot_params))

        snapshot_response = rds_client.describe_db_cluster_snapshots(
            **describe_db_snapshot_params)
        snapshots = snapshot_response['DBClusterSnapshots']
        while 'Marker' in snapshot_response:
            describe_db_snapshot_params['Marker'] = snapshot_response['Marker']
            snapshot_response = rds_client.describe_db_cluster_snapshots(
                **describe_db_snapshot_params)
            snapshots = snapshots + snapshot_response['DBClusterSnapshots']
        return snapshots
    except ClientError as err:
        raise MaskopyResourceException("Could not copy snapshot: %s" % err)

def get_db_snapshots_instance(rds_client, instance_identifier=None, snapshot_type=None, snapshot_identifier=None):
    """Return list of snapshots from an RDS cluster"""
    describe_db_snapshot_params = {}
    if instance_identifier:
        describe_db_snapshot_params['DBInstanceIdentifier'] = instance_identifier
    if snapshot_type:
        describe_db_snapshot_params['snapshot_type'] = snapshot_type
    if snapshot_identifier:
        describe_db_snapshot_params['DBSnapshotIdentifier'] = snapshot_identifier
    try:
        print('Getting DB snapshots with the following parameters: ')
        print(json.dumps(describe_db_snapshot_params))

        snapshot_response = rds_client.describe_db_snapshots(
            **describe_db_snapshot_params)
        snapshots = snapshot_response['DBSnapshots']
        while 'Marker' in snapshot_response:
            describe_db_snapshot_params['Marker'] = snapshot_response['Marker']
            snapshot_response = rds_client.describe_db_snapshots(
                **describe_db_snapshot_params)
            snapshots = snapshots + snapshot_response['DBSnapshots']
        return snapshots
    except ClientError as err:
        raise MaskopyResourceException("Could not copy snapshot: %s" % err)

def get_latest_snapshot_identifier(snapshot_list, engine):
    """Return snapshot to use based off latest available snapshot from a list of snapshots"""
    latest_date = None
    latest_snapshot = ''
    for snapshot in snapshot_list:
        if not snapshot['Status'] == 'available':
            continue
        if latest_date is None or snapshot['SnapshotCreateTime'] > latest_date:
            latest_date = snapshot['SnapshotCreateTime']
            if 'aurora' in engine:
                latest_snapshot = snapshot['DBClusterSnapshotIdentifier']
            else:
                latest_snapshot = snapshot['DBSnapshotIdentifier']
    return latest_snapshot

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