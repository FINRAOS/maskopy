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
    """Lambda handler for the seventh lambda of the Maskopy process.
    Args:
        event (dict): AWS Lambda uses this parameter to pass in event data to the handler.
        context (Context): AWS Lambda provides runtime info and meta data.
    Returns:
        bool: True if created instance is in available state, False otherwise.
    Raises:
        MaskopyDBInstanceStatusException: Exception raised if RDS creation has
            unexpected behavior.
    """
    for instance_identifier in event['DestinationRestoredDatabases']:
        instance_status = get_instance_status(RDS_CLIENT, instance_identifier)
        if instance_status != 'available':
            if instance_status in INSTANCE_STATUS_LIST:
                raise MaskopyDBInstanceStatusException(
                    f"RDS Instance Status: {instance_status}. Please check your input values.")
            return False
    return True

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
            DBInstanceIdentifier=instance_identifier)
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
    """Exception raised when AWS request returns a Throttling exception.
    """
