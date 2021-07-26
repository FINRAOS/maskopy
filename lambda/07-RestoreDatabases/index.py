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
    """Lambda handler for the seventh lambda of the Maskopy process.
    Args:
        event (dict): AWS Lambda uses this parameter to pass in event data to the handler.
        context (Context): AWS Lambda provides runtime info and meta data.
    Returns:
        (:obj:`list` of str) Instance identifier of the created RDS instances.
    """
    restored_dbs = []

    for snapshot in event['CreatedDestinationSnapshots']:
        restore_response = {}
        rds_identifier = ('MASKOPY-'
                          + event['ApplicationName'] + '-'
                          + snapshot['InstanceIdentifier'] + '-'
                          + str(int(time.time())))
        rds_instance_identifier = ('MASKOPY-'
                                   + event['ApplicationName'] + '-'
                                   + snapshot['InstanceIdentifier'] + '-'
                                   + str(int(time.time())))
        snapshot_parameters = {
            'snapshot': snapshot,
            'rds_identifier': rds_identifier[:63],
            'rds_instance_identifier':rds_instance_identifier[:63],
            'parameter_group_name': event['CreatedSnapshots'][0]['RdsParameterGroup'],
            'engine':  event['CreatedSnapshots'][0]['Engine'],
            'engine_version':  event['CreatedSnapshots'][0]['EngineVersion']
        }
        if event.get('RdsInstanceType'):
            snapshot_parameters['instance_type'] = event['RdsInstanceType']
        if event.get('RdsOptionGroup'):
            snapshot_parameters['option_group_name'] = event['RdsOptionGroup']

        print(f"RDS ID = {rds_instance_identifier}")
        restore_response = restore_rds_from_snapshot(**snapshot_parameters)

        if 'aurora' in event['CreatedSnapshots'][0]['Engine']:
            restored_dbs.append({
                'DBIdentifier':{
                    'DBClusterIdentifier' : restore_response['DBCluster']['DBClusterIdentifier'] ,
                    'DBInstanceIdentifier' : restore_response['DBInstance']['DBInstanceIdentifier']
                },
            })
        else:
            restored_dbs.append({
                'DBIdentifier':{
                    'DBInstanceIdentifier' :restore_response['DBInstance']['DBInstanceIdentifier']
                }
            })

    return restored_dbs


def restore_rds_from_snapshot(snapshot, rds_identifier, rds_instance_identifier,
                              parameter_group_name, engine, engine_version, instance_type=None, option_group_name=None
                              ):
    """Function to restore an instance from an rds snapshot, copying tags by default.
    Args:
        snapshot (dict of str:int): The snapshot dictionary.
        rds_instance_identifier (str): The destination instance identifier.
        parameter_group_name (str): The name of the parameter group in destination.
        option_group_name (str, optional): The name of the option group in destination.
        instance_type (str, optional): The instance type of the RDS instance.
    Returns:
        dict: Returns a dictionary of the created snapshot.
    Raises:
        MaskopyResourceException: Raised if resource cannot be accessed.
    """
    if 'aurora' in engine:
        snapshot_cluster_parameters = {
            'snapshot': snapshot,
            'cluster_identifier': rds_identifier,
            'rds_instance_identifier':rds_instance_identifier,
            'parameter_group_name': parameter_group_name,
            'engine':engine,
            'engine_version':engine_version
        }
        if instance_type:
            snapshot_cluster_parameters['instance_type'] = instance_type
        if option_group_name:
            snapshot_cluster_parameters['option_group_name'] = option_group_name
        return restore_rds_from_snapshot_cluster(**snapshot_cluster_parameters)
    else:
        snapshot_instance_parameters = {
            'snapshot': snapshot,
            'rds_instance_identifier':rds_instance_identifier,
            'parameter_group_name': parameter_group_name
        }
        if instance_type:
            snapshot_instance_parameters['instance_type'] = instance_type
        if option_group_name:
            snapshot_instance_parameters['option_group_name'] = option_group_name
        return restore_rds_from_snapshot_instance(**snapshot_instance_parameters)
def restore_rds_from_snapshot_cluster(snapshot, cluster_identifier, rds_instance_identifier,
                                      parameter_group_name, engine, engine_version, instance_type=None, option_group_name=None):
    """Function to restore an instance from an rds snapshot, copying tags by default.	
    Args:	
        snapshot (dict of str:int): The snapshot dictionary.	
        rds_instance_identifier (str): The destination instance identifier.	
        parameter_group_name (str): The name of the parameter group in destination.	
        option_group_name (str, optional): The name of the option group in destination.	
        instance_type (str, optional): The instance type of the RDS instance.	
    Returns:	
        dict: Returns a dictionary of the created snapshot.	
    Raises:	
        MaskopyResourceException: Raised if resource cannot be accessed.	
    """
    rds_client = boto3.client("rds")
    restore_snapshot_cluster_parameters = {
        'DBClusterIdentifier': cluster_identifier,
        'SnapshotIdentifier': snapshot['SnapshotARN'],
        'Engine':engine,
        'EngineVersion':engine_version,
        'DBSubnetGroupName': os.environ['subnet_group_name'],
        'VpcSecurityGroupIds': [os.environ['security_group']],
        'Tags': snapshot['SnapshotTags'],
        'DBClusterParameterGroupName': parameter_group_name,
        'CopyTagsToSnapshot': True
    }
    create_instance_parameters = {
        'DBInstanceIdentifier': rds_instance_identifier,
        'DBInstanceClass': instance_type,
        'Engine':engine,
        'DBClusterIdentifier' : cluster_identifier,
        'DBSubnetGroupName':os.environ['subnet_group_name']
    }
    if option_group_name:
        restore_snapshot_cluster_parameters['OptionGroupName'] = option_group_name
    try:
        print("Restoring DB with the following settings: ")
        print(json.dumps(restore_snapshot_cluster_parameters))
        cluster_response = rds_client.restore_db_cluster_from_snapshot(**restore_snapshot_cluster_parameters)
        instance_response= rds_client.create_db_instance(**create_instance_parameters)
        response= {**cluster_response , **instance_response}
        print(response)
        return response
    except ClientError as err:
        rds_client.delete_db_cluster(
            DBClusterIdentifier=cluster_identifier,
            SkipFinalSnapshot=True)
        # Check if error code is due to throttling.	
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        raise MaskopyResourceException(f"Could not copy snapshot: {err}")
def restore_rds_from_snapshot_instance(snapshot, rds_instance_identifier,
                                       parameter_group_name, option_group_name=None,
                                       instance_type=None):
    """Function to restore an instance from an rds snapshot, copying tags by default.	
    Args:	
        snapshot (dict of str:int): The snapshot dictionary.	
        rds_instance_identifier (str): The destination instance identifier.	
        parameter_group_name (str): The name of the parameter group in destination.	
        option_group_name (str, optional): The name of the option group in destination.	
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
        'DBParameterGroupName': parameter_group_name,
        'CopyTagsToSnapshot': True,
        'Tags': snapshot['SnapshotTags']
    }
    if option_group_name:
        restore_snapshot_parameters['OptionGroupName'] = option_group_name
    if instance_type:
        restore_snapshot_parameters['DBInstanceClass'] = instance_type
    try:
        print("Restoring DB with the following settings: ")
        print(json.dumps(restore_snapshot_parameters))
        return rds_client.restore_db_instance_from_db_snapshot(**restore_snapshot_parameters)
    except ClientError as err:
        # Check if error code is due to throttling.	
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        raise MaskopyResourceException(f"Could not copy snapshot: {err}")

class MaskopyResourceException(Exception):
    """Exception raised when IAM role or user is not able to access the
    resource.
    """
class MaskopyThrottlingException(Exception):
    """Exception raised when AWS request returns a Throttling exception.
    """