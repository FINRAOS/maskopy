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


This lambda checks the status of the RDS instance created in the destination environment.
This lambda expects the following inputs:
- DestinationRestoredDatabases
"""
import boto3
from botocore.exceptions import ClientError

RDS_CLIENT = boto3.client("rds")
INSTANCE_STATUS_LIST = [
    "incompatible-network",
    "incompatible-option-group",
    "incompatible-parameters",
    "incompatible-restore"
]

def lambda_handler(event, context):
    """Lambda handler for the eighth lambda of the Maskopy process.
    Args:
        event (dict): AWS Lambda uses this parameter to pass in event data to the handler.
        context (Context): AWS Lambda provides runtime info and meta data.
    Returns:
        bool: True if created instance is in available state, False otherwise.
    Raises:
        MaskopyDBInstanceStatusException: Exception raised if RDS creation has
            unexpected behavior.
    """
    rds_client = boto3.client("rds")
    engine=event['CreatedSnapshots'][0]['Engine']
    for rds_identifier in event['DestinationRestoredDatabases']:
        rds_status = get_rds_status(rds_client, rds_identifier,engine)
        if rds_status != 'available':
            if rds_status in INSTANCE_STATUS_LIST:
                raise MaskopyDBInstanceStatusException(
                    f"RDS Status: {instance_status}. Please check your input values.")
            return False
    return True
def get_rds_status(rds_client, rds_identifier,engine):
    """Function to query RDS instances to check if instance is in available status
    Args:
        rds_client (Client): AWS RDS Client object.
        instance_identifier (str): RDS instance identifier string.
    Returns:
        str: The status of the RDS instance specified by instance_identifier
    Raises:
        MaskopyThrottlingException: Exception used to catch throttling from AWS.
            Used to implement a back off strategy.
    """
    if 'aurora' in engine:
        return get_cluster_status(rds_client, rds_identifier)
    else:
        return get_instance_status(rds_client, rds_identifier)
def get_cluster_status(rds_client, rds_identifier):
    """Function to query RDS instances to check if instance is in available status
    Args:
        rds_client (Client): AWS RDS Client object.
        instance_identifier (str): RDS instance identifier string.
    Returns:
        str: The status of the RDS instance specified by instance_identifier
    Raises:
        MaskopyThrottlingException: Exception used to catch throttling from AWS.
            Used to implement a back off strategy.
    """
    try:
        describe_cluster_response = rds_client.describe_db_clusters(
            DBClusterIdentifier=rds_identifier['DBIdentifier']['DBClusterIdentifier'])
        describe_instance_response = rds_client.describe_db_instances(
            DBInstanceIdentifier=rds_identifier['DBIdentifier']['DBInstanceIdentifier'],
            Filters=[{
                'Name': 'db-cluster-id',
                'Values': [
                    rds_identifier['DBIdentifier']['DBClusterIdentifier']]
            }]
        )
        for cluster in describe_cluster_response['DBClusters']:
            cluster_status=cluster['Status']
        for instance in describe_instance_response['DBInstances']:
            instance_status=instance['DBInstanceStatus']
        if cluster_status and instance_status =='available':
            return 'available'
        elif instance_status != 'available':
            if instance_status in INSTANCE_STATUS_LIST:
                raise MaskopyDBInstanceStatusException(
                    f"RDS Status: {instance_status}. Please check your input values.")
        elif cluster_status != 'available':
            if cluster_status in CLUSTER_STATUS_LIST:
                raise MaskopyDBInstanceStatusException(
                    f"RDS Status: {cluster_status}. Please check your input values.")
    except ClientError as err:
        print(err.response['Error']['Code'])
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        print(err)
        raise
def get_instance_status(rds_client, instance_identifier):
    """Function to query RDS instances to check if instance is in available status
    Args:
        rds_client (Client): AWS RDS Client object.
        instance_identifier (str): RDS instance identifier string.
    Returns:
        str: The status of the RDS instance specified by instance_identifier
    Raises:
        MaskopyThrottlingException: Exception used to catch throttling from AWS.
            Used to implement a back off strategy.
    """
    try:
        describe_response = rds_client.describe_db_instances(
            DBInstanceIdentifier=instance_identifier['DBIdentifier']['DBInstanceIdentifier'])
        for instance in describe_response['DBInstances']:
            return instance['DBInstanceStatus']
    except ClientError as err:
        print(err.response['Error']['Code'])
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        print(err)
        raise
class MaskopyDBInstanceStatusException(Exception):
    """Exception raised when RDS is not in an available state.
    """
class MaskopyThrottlingException(Exception):
    """Exception raised when AWS Throttling Occurs.
    """