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


This lambda creates a Fargate task and a Fargate cluster.
This lambda expects the following inputs:
- ApplicationName
- DestinationRestoredDatabases
- ObfuscationScriptPath

Optional
- CustomTaskImage
- ExecutionTimestamp
"""
import os
import time

import boto3
from botocore.exceptions import ClientError

ECS_CLIENT = boto3.client('ecs')

def lambda_handler(event, context):
    """Lambda handler for the ninth lambda of the Maskopy process.
    Args:
        event (dict): AWS Lambda uses this parameter to pass in event data to the handler.
        context (Context): AWS Lambda provides runtime info and meta data.
    Returns:
        (dict of str:str) Dictionary containing cluster and task definition names.
    """
    application_name = event['ApplicationName']
    timestamp = event.get('ExecutionTimestamp') or str(int(time.time()))
    cluster_name = 'MASKOPY-FARGATE-CLUSTER'
    task_definition_name = f'maskopy-{application_name}-{timestamp}'
    task_definition_environment = [
        {
            'name': 'APPLICATION_NAME',
            'value': application_name
        },
        {
            'name': 'OBFUSCATION_SCRIPT_PATH',
            'value': event['ObfuscationScriptPath']
        },
        {
            'name': 'RDS_INSTANCE_IDENTIFIER',
            'value': event['DestinationRestoredDatabases'][0]['DBIdentifier']['DBInstanceIdentifier']
        },
        {
            'name': 'TIMESTAMP',
            'value': timestamp
        },
        {
            'name': 'ENGINE',
            'value': event['CreatedSnapshots'][0]['Engine']
        },
        {
            'name': 'SQL_SCRIPTS',
            'value': event.get('SqlScriptList') or ''
        },
        {
            'name': 'DB_NAME',
            'value': event.get('DbName') or ''
        },
        {
            'name': 'APP_NAME',
            'value': 'springboot'
        }
    ]
    create_cluster(cluster_name)

    create_log_group()

    task_definition_revision = create_task_definition(
        task_definition_name,
        task_definition_environment,
        event.get("TaskDefinitionCPU"),
        event.get("TaskDefinitionMemory"),
        event.get("CustomTaskImage")
    )

    return ({
        "ClusterName": cluster_name,
        "PlatformVersion": "1.4.0",
        "TaskDefinition": task_definition_name + ':' + task_definition_revision
    })

def create_cluster(cluster_name):
    """Function to create a cluster with cluster_name.
    Args:
        cluster_name (str): The name of the cluster to create.
    Returns:
        str: Returns the cluster name created.
    Raises:
        MaskopyResourceException: Raised if resource cannot be accessed
            or if the execution role does not have permissions to create resource.
        MaskopyThrottlingException: Exception used to catch throttling from AWS.
            Used to implement a back off strategy.
    """
    try:
        print(f'Cluster name is: {cluster_name}. Checking if it exists')
        response = ECS_CLIENT.describe_clusters(clusters=[
            cluster_name,
        ])
        if not response.get('clusters') or response.get('clusters')[0]['status'] == 'INACTIVE':
            print(f'Cluster does not exist. Creating Fargate cluster: {cluster_name}')

            response = ECS_CLIENT.create_cluster(
                clusterName=cluster_name
            )
        else:
            print('Cluster already exists.')
        return response
    except ClientError as err:
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        print(f'Failed to create Fargate cluster with error: {err}')
        raise MaskopyResourceException(f'Failed to create Fargate cluster: {err}')

def create_log_group():
    """Function to create the log group for the task definition.
    Raises:
        MaskopyResourceException: Raised if resource cannot be accessed
            or if the execution role does not have permissions to create resource.
        MaskopyThrottlingException: Exception used to catch throttling from AWS.
            Used to implement a back off strategy.
    """
    log_client = boto3.client("logs")
    try:
        log_response = log_client.describe_log_groups(
            logGroupNamePrefix="/ecs/maskopy/bootstrap-logs")
        if not log_response.get('logGroups'):
            print('Creating log group: /ecs/maskopy/bootstrap-logs')
            log_client.create_log_group(logGroupName="/ecs/maskopy/bootstrap-logs")
        else:
            print('/ecs/maskopy/bootstrap-logs log group already exists. Skipping creation.')

    except ClientError as err:
        # Check if error code is due to throttling.
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        print('Failed to create log group with error: ' + str(err))
        raise MaskopyResourceException(f"Failed to create log group: {err}")

def create_task_definition(task_definition_name, task_definition_environment, cpu, memory, image=None):
    """Function to create a task definition.
    Args:
        task_definition_name (str): The name of the cluster to create.
        task_definition_environment (:obj:`list` of :obj:`dict`):
            A list of dicts that contain the environment variables for task.
        image (str, optional): The name of the custom image to be used in task.
        cpu (str): Cpu variable for task definition
        memory (str): Memory Variable for task defintion
    Returns:
        str: Returns the revision number of the task created.
    Raises:
        MaskopyResourceException: Raised if resource cannot be accessed
            or if the execution role does not have permissions to create resource.
    """
    account_id = os.environ['account_id']
    default_image = os.environ['default_image']
    service_role = os.environ['service_role']
    region = os.environ['region']
    try:
        # Task definition name has a limit of 255 characters.
        print(f'Registering Task Definition: {task_definition_name[:255]}')
        response = ECS_CLIENT.register_task_definition(
            containerDefinitions=[
                {
                    'name': task_definition_name[:255],
                    'image': image or default_image,
                    'essential': True,
                    'memory': 1024,
                    'cpu': 80,
                    'logConfiguration': {
                        'logDriver': 'awslogs',
                        'options': {
                            'awslogs-group': '/ecs/maskopy/bootstrap-logs',
                            'awslogs-region': region,
                            'awslogs-stream-prefix': 'ecs'
                        }
                    },
                    'environment': task_definition_environment,
                    'command': [
                        '/tmp/config-bootstrap.sh'
                    ],
                    'workingDirectory': '/',
                }
            ],
            family=task_definition_name[:255],
            executionRoleArn=f'arn:aws:iam::{account_id}:role/{service_role}',
            taskRoleArn=f'arn:aws:iam::{account_id}:role/{service_role}',
            networkMode="awsvpc",
            requiresCompatibilities=["FARGATE"],
            memory=memory or "2048",
            cpu=cpu or "1024"
        )
        print(response)
        return str(response['taskDefinition']['revision'])
    except ClientError as err:
        print(f'Failed to register Task Definition with error: {err}')
        raise MaskopyResourceException(f'Failed to register Task Definition: ${err}')

class MaskopyResourceException(Exception):
    """Exception raised when IAM role or user is not able to access the
    resource.
    """

class MaskopyThrottlingException(Exception):
    """Exception raised when AWS request returns a Throttling exception.
    """
