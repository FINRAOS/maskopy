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


This lambda authenticates and checks if role executing the step function is
authorized to access the snapshot and other resources.
This provides security and access rules so unprotected execution and copying
does not occur.
This lambda expects the following inputs:
- ApplicationName
- RdsSnapshotIdentifier
- PresignedUrl
"""

import json
import os

import boto3
from botocore.vendored import requests
from botocore.exceptions import ClientError

STS_CLIENT = boto3.client("sts")
ASSUME_ROLE_ARN = os.environ['assume_role_arn']

def lambda_handler(event, context):
    """Lambda handler for the zeroth lambda of the Maskopy process.
    Args:
        event (dict): AWS Lambda uses this parameter to pass in event data to the handler.
        context (Context): AWS Lambda provides runtime info and meta data.
    Raises:
        MaskopyAccessException: Raise exception if IAM role or user does not have access
            to resource.
    """

    if not event['ApplicationName']:
        raise Exception(
            "Input 'ApplicationName' is missing. Please check your step function inputs."
        )

    # Create and assume a session in the source account.
    assume_role_session = create_account_session(
        STS_CLIENT,
        ASSUME_ROLE_ARN,
        context.aws_request_id
    )
    # Create an RDS client to source account.
    rds_client = assume_role_session.client('rds')

    application_name = event['ApplicationName']
    snapshot_identifier = event['RdsSnapshotIdentifier']
    url = event["PresignedUrl"]
    # Get tags from RDS snapshot. This is used to check user authorization.
    tags = get_rds_tags(rds_client, snapshot_identifier)
    # Get role from presigned url. This is used to authenticate the user.
    role = get_role_from_presigned_url(url)

    print(f"Running Maskopy with role: {role}.")
    try:
        snapshot_application_name = next(tag for tag in tags if tag["Key"] == "ApplicationName")["Value"]
    except:
        raise MaskopyAccessException(
            f"Snapshot({snapshot_identifier}) does not have 'ApplicationName' tag."
        )

    # Verify if the role contains the application name and
    # if the role contains the snapshot tag.
    if application_name.lower() not in role.lower():
        raise MaskopyAccessException(
            f"User role ({role}) does not match ApplicationName input: {application_name}")
    if snapshot_application_name.lower() not in role.lower():
        raise MaskopyAccessException(
            f"User role ({role}) is not authorized to access this snapshot: "
            f"{snapshot_application_name}")

    print("User successfully authorized!")

def get_role_from_presigned_url(url):
    """Function to retrieve role from presigned url.
    Args:
        url (str): Presigned url to request the role.
    Raises:
        MaskopyHTTPException: Raise exception if HTTP client POST request fails,
            or for any other general HTTP exception.
        MaskopyTimeoutException: Raise exception if HTTP client POST request times out.

    """
    # POST Request to url. Raise HTTP related exceptions as needed.
    try:
        request = requests.post(url, headers={'Accept': 'application/json'})
        request.raise_for_status()
    except requests.exceptions.HTTPError as err:
        raise MaskopyHTTPException(err)
    except requests.exceptions.Timeout:
        raise MaskopyTimeoutException("Request timed out.")
    except requests.exceptions.RequestException as err:
        raise MaskopyHTTPException(err)

    # Get the name of the role from the predefined url.
    data = json.loads(request.text)
    arn = data['GetCallerIdentityResponse']['GetCallerIdentityResult']['Arn']
    return arn.split('/')[1]

def get_rds_tags(rds_client, snapshot_identifier):
    """Function to retrieve list of tags from snapshot_identifier
    Args:
        rds_client (Client): AWS RDS Client object.
        snapshot_identifier (str): The RDS snapshot identifier
    Returns:
        :obj:`list` of :obj:`str`: The list of tags associated with snapshot,
            None otherwise.
    Raises:
        MaskopyThrottlingException: Exception used to catch throttling from AWS.
            Used to implement a back off strategy.
        MaskopyResourceNotFoundException: Exception raised if resource does not exist.
    """
    try:
        describe_db_response = rds_client.describe_db_snapshots(
            DBSnapshotIdentifier=snapshot_identifier)
        snapshot_arn = describe_db_response['DBSnapshots'][0]['DBSnapshotArn']

        list_tags_response = rds_client.list_tags_for_resource(
            ResourceName=snapshot_arn)

        return list_tags_response['TagList']
    except ClientError as err:
        # Check if error code is due to throttling.
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        print(f"Failed to get RDS tags for {snapshot_identifier}: {err}")
        raise MaskopyResourceNotFoundException(err)

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
        RoleSessionName=request_id)

    return boto3.session.Session(
        aws_access_key_id=sts_response['Credentials']['AccessKeyId'],
        aws_secret_access_key=sts_response['Credentials']['SecretAccessKey'],
        aws_session_token=sts_response['Credentials']['SessionToken']
    )

class MaskopyAccessException(Exception):
    """Exception raised when IAM role or user is not able to access the
    resource due to authorization error.
    """

class MaskopyResourceNotFoundException(Exception):
    """Exception raised when IAM role or user is not able to access the
    resource since the resource does not exist.
    """

class MaskopyHTTPException(Exception):
    """Exception raised when HTTP request returns a 4xx or 5xx error.
    """

class MaskopyTimeoutException(Exception):
    """Exception raised when HTTP request times out.
    """

class MaskopyThrottlingException(Exception):
    """Exception raised when AWS request returns a Throttling exception.
    """
