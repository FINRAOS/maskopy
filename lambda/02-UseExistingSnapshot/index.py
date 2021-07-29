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

    snapshots_created = []
    application_name = event["ApplicationName"]
    cost_center = event["CostCenter"]
    snapshot_identifier = event['CheckInputs']['firstSnapshotIdentifier']
    engine = event['Engine']
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
        new_snapshot_identifier, engine['Type'],
        snapshot_tags, CUSTOM_KMS_KEY)
    if 'aurora' in engine['Type']:
        snapshots_created.append({
            'SnapshotName': new_snapshot['DBClusterSnapshotIdentifier'],
            'SnapshotARN': new_snapshot['DBClusterSnapshotArn'],
            'InstanceIdentifier': new_snapshot['DBClusterIdentifier'],
            'Tags': snapshot_tags,
            'RdsParameterGroup': parameter_group,
            'Engine':engine['Type'],
            'EngineVersion':engine['Version']
        })
    else:
        snapshots_created.append({
            'SnapshotName': new_snapshot['DBSnapshotIdentifier'],
            'SnapshotARN': new_snapshot['DBSnapshotArn'],
            'InstanceIdentifier': new_snapshot['DBInstanceIdentifier'],
            'Tags': snapshot_tags,
            'RdsParameterGroup': parameter_group,
            'Engine': engine['Type'],
            'EngineVersion':engine['Version']
        })

    return snapshots_created

def check_snapshot_exists(rds_client, snapshot_identifier, engine):
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
    if "aurora" in engine:
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
def copy_db_snapshot(rds_client, snapshot_identifier,
                     new_snapshot_identifier, engine, snapshot_tags, kms_key=None):
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
    if 'aurora' in engine:
        return copy_db_snapshot_cluster(
            rds_client, snapshot_identifier,
            new_snapshot_identifier, engine,
            snapshot_tags, kms_key)
    else:
        return copy_db_snapshot_instance(
            rds_client, snapshot_identifier,
            new_snapshot_identifier, engine,
            snapshot_tags, kms_key)
def copy_db_snapshot_cluster(rds_client, source_db_snapshot_identifier,
                             destination_db_snapshot_identifier, engine, snapshot_tags, kms_key=None):
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
    copy_db_cluster_snapshot_parameters = {
        'SourceDBClusterSnapshotIdentifier': source_db_snapshot_identifier,
        'TargetDBClusterSnapshotIdentifier': destination_db_snapshot_identifier,
        'Tags': snapshot_tags
    }
    if kms_key:
        copy_db_cluster_snapshot_parameters['KmsKeyId'] = kms_key
    try:
        print("Copying DB snapshot with the following parameters: ")
        print(json.dumps(copy_db_cluster_snapshot_parameters))
        destination_snapshot_response = check_snapshot_exists(
            rds_client,
            destination_db_snapshot_identifier,
            engine)
        if not destination_snapshot_response:
            copy_db_snapshot_response = rds_client.copy_db_cluster_snapshot(
                **copy_db_cluster_snapshot_parameters)
            print(f"Successfully copied DB snapshot: {destination_db_snapshot_identifier}")
            return copy_db_snapshot_response['DBClusterSnapshot']
        print(f'{destination_db_snapshot_identifier} already exists. Using existing snapshot.')
        return destination_snapshot_response['DBClusterSnapshots'][0]
    except ClientError as err:
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        raise MaskopyResourceException("Could not copy snapshot: %s" % err)
def copy_db_snapshot_instance(rds_client, source_db_snapshot_identifier,
                              destination_db_snapshot_identifier, engine,snapshot_tags, kms_key=None):
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
            destination_db_snapshot_identifier,engine)
        if not destination_snapshot_response:
            copy_db_snapshot_response = rds_client.copy_db_snapshot(
                **copy_db_snapshot_parameters)
            print(f"Successfully copied DB snapshot: {destination_db_snapshot_identifier}")
            return copy_db_snapshot_response['DBSnapshot']
        print(f'{destination_db_snapshot_identifier} already exists. Using existing snapshot.')
        return destination_snapshot_response['DBSnapshots'][0]
    except ClientError as err:
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        raise MaskopyResourceException("Could not copy snapshot: %s" % err)
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
