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


This lambda restores the previously copied snapshot in the destination environment.
This lambda expects the following inputs:
- ApplicationName
- RdsParameterGroup

Optional:
- RdsInstanceType
- RdsOptionGroup
"""
import json
import os
import time

import boto3
from botocore.exceptions import ClientError

def lambda_handler(event, context):
    """Lambda handler for the sixth lambda of the Maskopy process.
    Args:
        event (dict): AWS Lambda uses this parameter to pass in event data to the handler.
        context (Context): AWS Lambda provides runtime info and meta data.
    Returns:
        (:obj:`list` of str) Instance identifier of the created RDS instances.
    """
    restored_dbs = []

    for snapshot in event['CreatedDestinationSnapshots']:
        restore_response = {}
        rds_instance_identifier = ('MASKOPY-'
                                   + event['ApplicationName'] + '-'
                                   + snapshot['InstanceIdentifier'] + '-'
                                   + str(int(time.time())))
        snapshot_parameters = {
            'snapshot': snapshot,
            'rds_instance_identifier': rds_instance_identifier[:63],
            'db_parameter_group_name': event['CreatedSnapshots'][0]['RdsParameterGroup']
        }
        if event.get('RdsInstanceType'):
            snapshot_parameters['instance_type'] = event['RdsInstanceType']
        if event.get('RdsOptionGroup'):
            snapshot_parameters['db_option_group_name'] = event['RdsOptionGroup']

        print(f"RDS ID = {rds_instance_identifier}")
        restore_response = restore_rds_from_snapshot(**snapshot_parameters)

        restored_dbs.append(restore_response['DBInstance']['DBInstanceIdentifier'])

    return restored_dbs


def restore_rds_from_snapshot(snapshot, rds_instance_identifier,
                              db_parameter_group_name, db_option_group_name=None,
                              instance_type=None):
    """Function to restore an instance from an rds snapshot, copying tags by default.
    Args:
        snapshot (dict of str:int): The snapshot dictionary.
        rds_instance_identifier (str): The destination instance identifier.
        db_parameter_group_name (str): The name of the parameter group in destination.
        db_option_group_name (str, optional): The name of the option group in destination.
        instance_type (str, optional): The instance type of the RDS instance.
    Returns:
        dict: Returns a dictionary of the created snapshot.
    Raises:
        MaskopyResourceException: Raised if resource cannot be accessed.
    """
    rds_client = boto3.client("rds")
    restore_snapshot_parameters = {
        'DBSnapshotIdentifier': snapshot['SnapshotARN'],
        'DBSubnetGroupName': os.environ['subnet_group_name'],
        'DBInstanceIdentifier': rds_instance_identifier,
        'VpcSecurityGroupIds': [os.environ['security_group']],
        'DBParameterGroupName': db_parameter_group_name,
        'CopyTagsToSnapshot': True,
        'Tags': snapshot['SnapshotTags']
    }

    if db_option_group_name:
        restore_snapshot_parameters['OptionGroupName'] = db_option_group_name
    if instance_type:
        restore_snapshot_parameters['DBInstanceClass'] = instance_type

    try:

        print("Restoring DB with the following settings: ")
        print(json.dumps(restore_snapshot_parameters))
        return rds_client.restore_db_instance_from_db_snapshot(**restore_snapshot_parameters)
    except ClientError as err:
        raise MaskopyResourceException("Could not copy snapshot: %s" % err)

class MaskopyResourceException(Exception):
    """Exception raised when IAM role or user is not able to access the
    resource.
    """
