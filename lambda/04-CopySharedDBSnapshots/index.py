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


This lambda creates a copy of the previously shared snapshot in the destination environment.
This lambda expects the following inputs:
- CreatedSnapshots
"""
import json
import os

import boto3
from botocore.exceptions import ClientError

RDS_CLIENT = boto3.client("rds")
DEFAULT_KMS_KEY = os.environ['destination_account_default_kms_key_arn']

def lambda_handler(event, context):
    """Lambda handler for the fourth lambda of the Maskopy process.
    Args:
        event (dict): AWS Lambda uses this parameter to pass in event data to the handler.
        context (Context): AWS Lambda provides runtime info and meta data.
    Returns:
        :obj:`list` of :obj:`dict`: Returns a list of snapshots created in destination environment.
    """
    snapshots_to_create = []
    snapshots_created = []

    for snapshot in event['CreatedSnapshots']:
        print("InstanceIdentifier = " + snapshot['InstanceIdentifier'])
        snapshots_to_create.append({
            'SnapshotIdentifier': snapshot['SnapshotARN'],
            'InstanceIdentifier': snapshot['InstanceIdentifier'],
            'SnapshotName': snapshot['SnapshotName'] + context.aws_request_id,
            'SnapshotTags': snapshot['Tags']
        })

    for snapshot in snapshots_to_create:
        new_snapshot = copy_db_snapshot(
            RDS_CLIENT,
            snapshot['SnapshotIdentifier'],
            snapshot['SnapshotName'],
            snapshot['SnapshotTags'],
            DEFAULT_KMS_KEY
        )
        snapshots_created.append({
            'SnapshotName': new_snapshot['DBSnapshotIdentifier'],
            'InstanceIdentifier': new_snapshot['DBInstanceIdentifier'],
            'SnapshotARN': new_snapshot['DBSnapshotArn'],
            'SnapshotTags': snapshot['SnapshotTags']
        })

    return snapshots_created


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
    # Note: CopyTags parameter cannot be used on shared snapshots.
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

        copy_db_snapshot_response = rds_client.copy_db_snapshot(
            **copy_db_snapshot_parameters)
        return copy_db_snapshot_response['DBSnapshot']
    except ClientError as err:
        raise MaskopyResourceException(f'Could not copy snapshot: {err}')

class MaskopyResourceException(Exception):
    """Exception raised when IAM role or user is not able to access the
    resource.
    """
