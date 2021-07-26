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


This lambda shares the created temporary snapshot with the destination account.
This lambda expects the following inputs:
- CreatedSnapshots
"""
import json
import os

import boto3
from botocore.exceptions import ClientError

STS_CLIENT = boto3.client("sts")
ACCOUNT_LIST = os.environ['accounts_to_share_with'].split(',')
ASSUME_ROLE_ARN = os.environ['assume_role_arn']

def lambda_handler(event, context):
    """Lambda handler for the fourth lambda of the Maskopy process.
    Args:
        event (dict): AWS Lambda uses this parameter to pass in event data to the handler.
        context (Context): AWS Lambda provides runtime info and meta data.
    Returns:
        bool: True if snapshots are shared successfully, False otherwise.
    """
    assume_role_session = create_account_session(
        STS_CLIENT, ASSUME_ROLE_ARN, context.aws_request_id)
    rds_client = assume_role_session.client('rds')
    return share_snapshots(rds_client, event['CreatedSnapshots'], ACCOUNT_LIST)

def share_snapshots(rds_client, snapshots, account_list):
    """Function to modify and snapshots across accounts.
    Args:
        rds_client (Client): AWS RDS Client object.
        snapshots (:obj:`list` of :obj:`str`): A list of snapshot identifiers.
        account_list (:obj:`list` of :obj`str`): A list of account numbers to share with.
    Returns:
        bool: True if snapshot was shared, False otherwise.
    Raises:
        MaskopyThrottlingException: Exception used to catch throttling from AWS.
            Used to implement a back off strategy.
    """
    print('Sharing snapshots: ')
    print(json.dumps(snapshots))
    print('Shared accounts: ')
    print(*account_list, sep=", ")
    for snapshot in snapshots:
        try:
            rds_client.modify_db_snapshot_attribute(
                DBSnapshotIdentifier=snapshot['SnapshotName'],
                AttributeName='restore',
                ValuesToAdd=account_list
            )
        except ClientError as err:
            # Check if error code is due to throttling.
            if err.response['Error']['Code'] == 'Throttling':
                print("Throttling occurring.")
                raise MaskopyThrottlingException(err)
            elif  err.response['Error']['Code']=='DBSnapshotNotFound':
                try:
                    rds_client.modify_db_cluster_snapshot_attribute(
                        DBClusterSnapshotIdentifier=snapshot['SnapshotName'],
                        AttributeName='restore',
                        ValuesToAdd=account_list
                    )
                except ClientError as err:
                    if err.response['Error']['Code'] == 'Throttling':
                        print("Throttling occurring.")
                        raise MaskopyThrottlingException(err)
                    print('Could not share snapshot with account.')
                    print(err)
                    raise
            else:
                print('Could not share snapshot with account.')
                print(err)
                raise
    return True

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
