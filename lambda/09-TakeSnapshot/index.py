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


This lambda takes a snapshot of the obfuscated RDS instance and databases.
This lambda expects the following inputs:
- ApplicationName
- CreatedSnapshots
- DestinationRestoredDatabases
- InstanceIdentifier
- RdsFinalSnapshotIdentifier
"""
import time

import boto3
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    """Lambda handler for the ninth lambda of the Maskopy process.
    Args:
        event (dict): AWS Lambda uses this parameter to pass in event data to the handler.
        context (Context): AWS Lambda provides runtime info and meta data.
    Returns:
        (:obj:`list` of :obj:`dict`) List of one dictionary containing generated snapshot name.
    """
    application_name = event['ApplicationName']
    generated_database = event['DestinationRestoredDatabases'][0]
    db_identifier = event['CreatedSnapshots'][0]['InstanceIdentifier']
    rds_client = boto3.client('rds')

    # Check if snapshot name is valid.
    if ("RdsFinalSnapshotIdentifier" in event and
            event['RdsFinalSnapshotIdentifier'].startswith(application_name.lower())):
        # If final snapshot name is provided and is valid, use the final snapshot name.
        snapshot_name = event['RdsFinalSnapshotIdentifier']
    else:
        print("Final snapshot name is not provided or is not valid, using default..")
        snapshot_name = generate_snapshot_name(db_identifier, application_name)

    return [create_snapshot(rds_client, generated_database, snapshot_name)]

def generate_snapshot_name(db_name, application_name):
    """Function to generate a snapshot name.
    Args:
        db_name (str): The name of the original db of the snapshot.
        application_name (str): The name of the application.
    Returns:
        str: The generated snapshot name in the format
            {application_name}-{db_name}-{timestamp}.
    """
    snapshot_time = int(time.time())
    return f'{application_name.lower()}-{db_name}-{str(snapshot_time)}'

def create_snapshot(rds_client, db_name, snapshot_name):
    """Function to create a copy of a rds snapshot, copying tags by default.
    Args:
        rds_client (Client): AWS RDS Client object.
        db_name (str): The source RDS instance identfier.
        snapshot_name (str): The final snapshot name.
    Returns:
        :dict`: Returns a dict of the created snapshot.
    Raises:
        MaskopyResourceException: Raised if resource cannot be accessed.
    """
    try:
        # RDS snapshot name has a limit of 255 characters.
        response = rds_client.create_db_snapshot(
            DBSnapshotIdentifier=snapshot_name[:255],
            DBInstanceIdentifier=db_name
        )
        return {'SnapshotName': response['DBSnapshot']['DBSnapshotIdentifier']}

    except ClientError as err:
        raise MaskopyResourceException(f'Could not create snapshot: {err}')

class MaskopyResourceException(Exception):
    """Exception raised when IAM role or user is not able to access the
    resource.
    """
