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


This lambda checks the status of the snapshot creation in the source environment.
This lambda expects the following inputs:
- CreatedSnapshots
"""
import json
import os

import boto3
from botocore.exceptions import ClientError

STS_CLIENT = boto3.client("sts")
ASSUME_ROLE_ARN = os.environ['assume_role_arn']

def lambda_handler(event, context):
    """Lambda handler for the third lambda of the Maskopy process.
    Args:
        event (dict): AWS Lambda uses this parameter to pass in event data to the handler.
        context (Context): AWS Lambda provides runtime info and meta data.
    Returns:
        bool: True if snapshots are in available state, False otherwise.
    """
    completed_snapshots = []

    assume_role_session = create_account_session(
        STS_CLIENT, ASSUME_ROLE_ARN, context.aws_request_id)
    rds_client = assume_role_session.client('rds')
    engine = event['CreatedSnapshots'][0]['Engine']

    # Check status of snapshots in CreatedSnapshots input.
    for snapshot in event['CreatedSnapshots']:
        snapshot_info = get_db_snapshots(
            rds_client, engine, None, None, snapshot['SnapshotName'])
        for info in snapshot_info:
            if info['Status'] == 'available':
                completed_snapshots.append('snapshot')

    if len(completed_snapshots) == len(event['CreatedSnapshots']):
        return True
    return False

def get_db_snapshots(rds_client, engine, rds_identifier=None,
                     snapshot_type=None, snapshot_identifier=None):
    """Function to query snapshots to check if snapshots are in available status
    Args:
        rds_client (Client): AWS RDS Client object.
        rds_identifier (str, optional): RDS instance or cluster identifier string.
            If specified, will list all snapshots belonging to this instance.
        snapshot_type (str, optional): RDS snapshot type.
            Required if snapshot is an automated snapshot.
        snapshot_identifier (str, optional): RDS snapshot identifer.
            Cannot be used in conjunction with instance_identifier.
    Returns:
        :obj:`list` of :obj:`dict`: A list of snapshots.
            None if no snapshots exist with specified parameters.
    Raises:
        MaskopyThrottlingException: Exception used to catch throttling from AWS.
            Used to implement a back off strategy.
    """
    if 'aurora' in engine:
        return  get_db_snapshots_cluster(rds_client,rds_identifier, snapshot_type, snapshot_identifier)
    else:
        return  get_db_snapshots_instance(rds_client,rds_identifier, snapshot_type, snapshot_identifier)
def get_db_snapshots_cluster(rds_client, cluster_identifier=None, snapshot_type=None, snapshot_identifier=None):
    """Return a list of cluster snapshots that were created in UseExistingSnapshot step"""
    describe_db_snapshot_params = {}
    if cluster_identifier:
        describe_db_snapshot_params['DBClusterIdentifier'] = cluster_identifier
    if snapshot_type:
        describe_db_snapshot_params['snapshot_type'] = snapshot_type
    if snapshot_identifier:
        describe_db_snapshot_params['DBClusterSnapshotIdentifier'] = snapshot_identifier
    try:
        print('Getting DB snapshots with the following parameters: ')
        print(json.dumps(describe_db_snapshot_params))
        snapshot_response = rds_client.describe_db_cluster_snapshots(
            **describe_db_snapshot_params)
        snapshots = snapshot_response['DBClusterSnapshots']
        # Paginate the rds response, if required.
        while 'Marker' in snapshot_response:
            describe_db_snapshot_params['Marker'] = snapshot_response['Marker']
            snapshot_response = rds_client.describe_db_cluster_snapshots(
                **describe_db_snapshot_params)
            snapshots = snapshots + snapshot_response['DBClusterSnapshots']
    except ClientError as err:
        # Check if error code is due to throttling.
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        print(f"Failed to get DB Cluster Snapshots: {err}")
        raise
    return snapshots
def get_db_snapshots_instance(rds_client, instance_identifier=None, snapshot_type=None, snapshot_identifier=None):
    """Return a list of cluster snapshots that were created in UseExistingSnapshot step"""
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
    except ClientError as err:
        # Check if error code is due to throttling.
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        print(f"Failed to get DB Instance Snapshots: {err}")
        raise
    return snapshots

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
