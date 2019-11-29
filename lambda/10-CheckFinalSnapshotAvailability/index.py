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


This lambda checks the status of the snapshot copied to the destination environment.
This lambda expects the following inputs:
- CreatedFinalSnapshots
"""
import json

import boto3
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    """Lambda handler for the tenth lambda of the Maskopy process.
    Args:
        event (dict): AWS Lambda uses this parameter to pass in event data to the handler.
        context (Context): AWS Lambda provides runtime info and meta data.
    Returns:
        bool: True if final snapshots are in available state, False otherwise.
    """
    completed_snapshots = []
    rds_client = boto3.client("rds")
    # Check availability state of the snapshots in the list of created snapshots
    for snapshot in event['CreatedFinalSnapshots']:
        snapshot_info = get_db_snapshots(
            rds_client, None, None, snapshot['SnapshotName'])
        for info in snapshot_info:
            if info['Status'] == 'available':
                completed_snapshots.append('snapshot')

    if len(completed_snapshots) == len(event['CreatedFinalSnapshots']):
        return True
    return False

def get_db_snapshots(rds_client, instance_identifier=None,
                     snapshot_type=None, snapshot_identifier=None):
    """Function to query snapshots to check if snapshots are in available status
    Args:
        rds_client (Client): AWS RDS Client object.
        instance_identifier (str, optional): RDS instance identifier string.
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
    describe_db_snapshot_params = {}
    if instance_identifier:
        describe_db_snapshot_params['DBInstanceIdentifier'] = instance_identifier
    if snapshot_type:
        describe_db_snapshot_params['SnapshotType'] = snapshot_type
    if snapshot_identifier:
        describe_db_snapshot_params['DBSnapshotIdentifier'] = snapshot_identifier

    try:
        print('Getting DB snapshots with the following parameters:')
        print(json.dumps(describe_db_snapshot_params))

        snapshot_response = rds_client.describe_db_snapshots(
            **describe_db_snapshot_params)
        snapshots = snapshot_response['DBSnapshots']

        # Paginate the rds response, if required.
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
        print(f"Failed to get DB Snapshots: {err}")
        raise

    return snapshots

class MaskopyThrottlingException(Exception):
    """Exception raised when AWS request returns a Throttling exception.
    """
