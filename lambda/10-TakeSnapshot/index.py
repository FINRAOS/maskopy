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
    engine=event['CreatedSnapshots'][0]['Engine']
    # If obfuscation run mode was set to none, then Maskopy needs to create a copy of the	
    # shared snapshot from the source environment.	
    if event.get('ObfuscateRunMode') == 'none' and event.get('DestinationEnv') == 'dev':
        for snapshot in event['CreatedSnapshots']:
            print("InstanceIdentifier = " + snapshot['InstanceIdentifier'])
            snapshots_to_create.append({
                'SnapshotIdentifier': snapshot['SnapshotARN'],
                'InstanceIdentifier': snapshot['InstanceIdentifier'],
                'SnapshotName': snapshot_name,
                'SnapshotTags': snapshot['Tags']
            })
        for snapshot in snapshots_to_create:
            new_snapshot = copy_db_snapshot(
                rds_client,
                snapshot['SnapshotIdentifier'],
                snapshot['SnapshotName'],
                snapshot['SnapshotTags'],
                engine,
                os.environ['destination_account_default_kms_key_arn']
            )
            if 'aurora' in engine:
                snapshots_created.append({
                    'SnapshotName': new_snapshot['DBClusterSnapshotIdentifier'],
                    'InstanceIdentifier': new_snapshot['DBClusterIdentifier'],
                    'SnapshotARN': new_snapshot['DBClusterSnapshotArn']
                })
            else:
                snapshots_created.append({
                    'SnapshotName': new_snapshot['DBSnapshotIdentifier'],
                    'InstanceIdentifier': new_snapshot['DBInstanceIdentifier'],
                    'SnapshotARN': new_snapshot['DBSnapshotArn'],
                    'SnapshotTags': snapshot['SnapshotTags']
                })
        return snapshots_created
    return [create_snapshot(rds_client, event['DestinationRestoredDatabases'][0]['DBIdentifier'], snapshot_name,engine)]
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
def copy_db_snapshot(rds_client, source_db_snapshot_identifier,
                     destination_db_snapshot_identifier, snapshot_tags, engine, kms_key=None):
    if 'aurora' in engine:
        return  copy_db_cluster_snapshot(rds_client, source_db_snapshot_identifier,
                                         destination_db_snapshot_identifier, snapshot_tags, kms_key)
    else:
        return  copy_db_instance_snapshot(rds_client, source_db_snapshot_identifier,
                                          destination_db_snapshot_identifier, snapshot_tags, kms_key)
def copy_db_cluster_snapshot(rds_client, source_db_snapshot_identifier,
                             destination_db_snapshot_identifier, snapshot_tags, kms_key=None):
    """Function to create a copy of a rds snapshot, copying tags by default.	
    Args:	
        rds_client (Client): AWS RDS Client object.	
        source_db_snapshot_identifier (str): The source snapshot identifier.	
        destination_db_snapshot_identifier (str): The destination snapshot identifier.	
        snapshot_tags (:obj:`list` of :obj:`dict`):	
            A list of dicts that contain the tags for the snapshot.	
        kms_key (str, optional): KMS Key to encrypt snapshot.	
    Returns:	
        :dict: Returns a dict of the created snapshot.	
    Raises:	
        MaskopyResourceException: Raised if resource cannot be accessed.	
    """
    # Note: CopyTags parameter cannot be used on shared snapshots.	
    copy_db_snapshot_parameters = {
        'SourceDBClusterSnapshotIdentifier': source_db_snapshot_identifier,
        'TargetDBClusterSnapshotIdentifier': destination_db_snapshot_identifier,
        'Tags': snapshot_tags
    }
    if kms_key:
        copy_db_snapshot_parameters['KmsKeyId'] = kms_key
    try:
        print("Copying DB snapshot with the following parameters: ")
        print(json.dumps(copy_db_snapshot_parameters))
        copy_db_snapshot_response = rds_client.copy_db_cluster_snapshot(
            **copy_db_snapshot_parameters)
        return copy_db_snapshot_response['DBClusterSnapshot']
    except ClientError as err:
        # Check if error code is due to throttling.	
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        raise MaskopyResourceException(f'Could not copy snapshot: {err}')
def copy_db_instance_snapshot(rds_client, source_db_snapshot_identifier,
                              destination_db_snapshot_identifier, snapshot_tags, kms_key=None):
    """Function to create a copy of a rds snapshot, copying tags by default.	
    Args:	
        rds_client (Client): AWS RDS Client object.	
        source_db_snapshot_identifier (str): The source snapshot identifier.	
        destination_db_snapshot_identifier (str): The destination snapshot identifier.	
        snapshot_tags (:obj:`list` of :obj:`dict`):	
            A list of dicts that contain the tags for the snapshot.	
        kms_key (str, optional): KMS Key to encrypt snapshot.	
    Returns:	
        :dict: Returns a dict of the created snapshot.	
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
        # Check if error code is due to throttling.	
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        raise MaskopyResourceException(f'Could not copy snapshot: {err}')
def create_snapshot(rds_client, db_name, snapshot_name, engine):
    """Function to create a copy of a rds snapshot, copying tags by default.	
    Args:	
        rds_client (Client): AWS RDS Client object.	
        db_name (str): The source RDS instance identfier.	
        snapshot_name (str): The final snapshot name.
        engine: The DB engine of the snapshot
    Returns:	
        :dict: Returns a dict of the created snapshot.	
    Raises:	
        MaskopyResourceException: Raised if resource cannot be accessed.	
    """
    if "aurora" in engine:
        return create_snapshot_cluster(rds_client, db_name, snapshot_name)
    else :
        return create_snapshot_instance(rds_client, db_name, snapshot_name)
def create_snapshot_cluster(rds_client, db_name, snapshot_name):
    """Function to create a copy of a rds snapshot, copying tags by default.	
    Args:	
        rds_client (Client): AWS RDS Client object.	
        db_name (str): The source RDS instance identfier.	
        snapshot_name (str): The final snapshot name.	
    Returns:	
        :dict: Returns a dict of the created snapshot.	
    Raises:	
        MaskopyResourceException: Raised if resource cannot be accessed.	
    """
    try:
        # RDS snapshot name has a limit of 255 characters.	
        response = rds_client.create_db_cluster_snapshot(
            DBClusterSnapshotIdentifier=snapshot_name[:255],
            DBClusterIdentifier=db_name["DBClusterIdentifier"]
        )
        return {'SnapshotName': response['DBClusterSnapshot']['DBClusterSnapshotIdentifier']}
    except ClientError as err:
        # Check if error code is due to throttling.	
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        raise MaskopyResourceException(f'Could not create cluster snapshot: {err}')
def create_snapshot_instance(rds_client, db_name, snapshot_name):
    """Function to create a copy of a rds snapshot, copying tags by default.	
    Args:	
        rds_client (Client): AWS RDS Client object.	
        db_name (str): The source RDS instance identfier.	
        snapshot_name (str): The final snapshot name.	
    Returns:	
        :dict: Returns a dict of the created snapshot.	
    Raises:	
        MaskopyResourceException: Raised if resource cannot be accessed.	
    """
    try:
        # RDS snapshot name has a limit of 255 characters.	
        response = rds_client.create_db_snapshot(
            DBSnapshotIdentifier=snapshot_name[:255],
            DBInstanceIdentifier=db_name["DBInstanceIdentifier"]
        )
        return {'SnapshotName': response['DBSnapshot']['DBSnapshotIdentifier']}
    except ClientError as err:
        # Check if error code is due to throttling.	
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        raise MaskopyResourceException(f'Could not create instance snapshot: {err}')
class MaskopyResourceException(Exception):
    """Exception raised when IAM role or user is not able to access the	
    resource.	
    """
class MaskopyThrottlingException(Exception):
    """Exception raised when AWS request returns a Throttling exception.	
    """