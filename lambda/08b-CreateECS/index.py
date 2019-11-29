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


This lambda creates an ECS cluster, an ECS task, an ASG, and a launch configuration.
This lambda expects the following inputs:
- ApplicationName
- AmiId
- CostCenter
- DestinationEnv
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
ASG_CLIENT = boto3.client('autoscaling')

def lambda_handler(event, context):
    """Lambda handler for the eighth lambda of the Maskopy process.
    Args:
        event (dict): AWS Lambda uses this parameter to pass in event data to the handler.
        context (Context): AWS Lambda provides runtime info and meta data.
    Returns:
        (dict of str:str) Dictionary containing cluster and task definition names.
    """
    application_name = event['ApplicationName']
    timestamp = event.get('ExecutionTimestamp') or str(int(time.time()))
    destination_env = event['DestinationEnv']
    cluster_name = f'MASKOPY-ECS-CLUSTER-{application_name}-{timestamp}'
    task_definition_name = f'maskopy-{application_name}-{timestamp}'
    asg_name = f'MASKOPY-{application_name}-ecs-{destination_env}-{timestamp}'
    ec2_name = f'AWSLX{application_name}-OBFUSCATEE{destination_env[0].upper()}01'
    asg_tags = [
        {
            'ResourceType': 'auto-scaling-group',
            'Key': 'Name',
            'Value': ec2_name,
            'PropagateAtLaunch': True
        },
        {
            'ResourceType': 'auto-scaling-group',
            'Key': 'ApplicationName',
            'Value': 'MASKOPY',
            'PropagateAtLaunch': True
        },
        {
            'ResourceType': 'auto-scaling-group',
            'Key': 'Cost Center',
            'Value': event['CostCenter'],
            'PropagateAtLaunch': True
        },
        {
            'ResourceType': 'auto-scaling-group',
            'Key': 'SDLC',
            'Value': destination_env,
            'PropagateAtLaunch': True
        },
        {
            'ResourceType': 'auto-scaling-group',
            'Key': 'ecs_clustername',
            'Value': cluster_name,
            'PropagateAtLaunch': True
        },
        {
            'ResourceType': 'auto-scaling-group',
            'Key': 'Role',
            'Value': 'ecs_privatenat',
            'PropagateAtLaunch': True
        }
    ]
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
            'value': event['DestinationRestoredDatabases'][0]
        },
        {
            'name': 'TIMESTAMP',
            'value': timestamp
        }
    ]

    cluster_name = create_cluster(cluster_name)

    # Check if old ASG and old launch configurations exist and delete them.
    remove_existing_asg_resources(asg_name, asg_name)
    create_log_group()

    launch_configuration_id = create_launch_configuration(asg_name, event['AmiId'])
    instance_id = create_asg(asg_name, launch_configuration_id, asg_tags)

    task_definition_revision = create_task_definition(
        task_definition_name,
        task_definition_environment,
        event.get("CustomTaskImage"))

    return ({
        "ClusterName": cluster_name,
        "TaskDefinition": task_definition_name + ':' + task_definition_revision,
        "InstanceId": instance_id,
        "AsgName": asg_name
    })

def create_cluster(cluster_name):
    """Function to restore an instance from an rds snapshot, copying tags by default.
    Args:
        cluster_name (str): The name of the cluster to create.
    Returns:
        str: Returns the cluster name created.
    Raises:
        MaskopyResourceException: Raised if resource cannot be accessed
            or if the execution role does not have permissions to create resource.
    """
    try:
        # ECS cluster name has a 255 character limit.
        print(f'Creating ECS cluster: {cluster_name[:255]}')
        response = ECS_CLIENT.create_cluster(clusterName=cluster_name[:255])
        return response['cluster']['clusterName']

    except ClientError as err:
        print(f'Failed to create ECS cluster with error: {err}')
        raise MaskopyResourceException(f'Failed to create ECS cluster: {err}')

def remove_existing_asg_resources(asg_name, launch_configuration_id):
    """Function to check if ASG resources exists, if so remove them.
    Args:
        asg_name (str): The name of the ASG to check.
        launch_configuration_id (str): The name of the launch configuration
            used to create the instances in the ASG.
    Returns:
        bool: True if the ASG resources were deleted or if they do not exist,
            False otherwise.
    Raises:
        MaskopyResourceException: Raised if resource cannot be accessed
            or if the execution role does not have permissions to create resource.
        MaskopyThrottlingException: Exception used to catch throttling from AWS.
            Used to implement a back off strategy.
    """
    try:
        asg_response = ASG_CLIENT.describe_auto_scaling_groups(
            AutoScalingGroupNames=[asg_name])
        if asg_response['AutoScalingGroups']:
            print("Found an existing asg with same name, deleting it.")
            ASG_CLIENT.delete_auto_scaling_group(
                AutoScalingGroupName=asg_name,
                ForceDelete=True)
        # Wait for ASG to delete or trigger a delete. If wait wasn't here, then
        # ASG might not be in deletion state. The launch configuration deletion
        # will throw an error if ASG is not in deletion state.
        time.sleep(40)

        #check if an old launch configuration exists and delete it
        launch_configuration_response = ASG_CLIENT.describe_launch_configurations(
            LaunchConfigurationNames=[launch_configuration_id])
        if launch_configuration_response['LaunchConfigurations']:
            print("Found an existing Launch Configuration with same name, deleting it.")
            ASG_CLIENT.delete_launch_configuration(
                LaunchConfigurationName=launch_configuration_id)
        return True

    except ClientError as err:
        # Check if error code is due to throttling.
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        print(f'Failed to delete ASG or Launch Configuration with error: {err}')
        raise MaskopyResourceException(f'Failed to delete ASG or Launch Configuration: {err}')

def create_launch_configuration(asg_name, ami_id):
    """Function to create a launch configuration.
    Args:
        task_definition_name (str): The name of the cluster to create.
        task_definition_environment (:obj:`list` of :obj:`dict`):
            A list of dicts that contain the environment variables for task.
    Returns:
        str: Returns the revision number of the task created.
    Raises:
        MaskopyResourceException: Raised if resource cannot be accessed
            or if the execution role does not have permissions to create resource.
    """
    print(f'Creating new Launch Configuration: {asg_name}')
    try:
        key_name = os.environ['ec2_keypair']
        security_groups = os.environ['ec2_security_groups']
        ASG_CLIENT.create_launch_configuration(
            LaunchConfigurationName=asg_name,
            ImageId=ami_id,
            KeyName=key_name,
            SecurityGroups=str(security_groups).split(','),
            InstanceType='t2.medium',
            IamInstanceProfile='APP_MASKOPY')
        return asg_name

    except ClientError as err:
        print(f'Failed to create Launch Configuration with error: {err}')
        raise MaskopyResourceException(f'Failed to create launch Configuration: ${err}')

def create_asg(asg_name, launch_configuration_id, asg_tags):
    """Function to create an ASG with a single instance
    Args:
        asg_name (str): The name of the ASG to create.
        launch_configuration_id (str): The name of the launch configuration
            used to create the instances in the ASG.
        asg_tags (:obj:`list` of :obj:`dict`):
            A list of dicts that contain the tags for the ASG.
    Returns:
        str: Returns the EC2 instance ID created by ASG.
    Raises:
        MaskopyResourceException: Raised if resource cannot be accessed
            or if the execution role does not have permissions to create resource.
        MaskopyThrottlingException: Exception used to catch throttling from AWS.
            Used to implement a back off strategy.
    """
    ec2_client = boto3.client('ec2')
    ec2_waiter = ec2_client.get_waiter('instance_running')

    try:
        subnet_ids = os.environ['ec2_subnets']

        # Call ASG_CLIENT and create ASG.
        print(f'Creating new ASG: {asg_name}')
        response = ASG_CLIENT.create_auto_scaling_group(
            AutoScalingGroupName=asg_name,
            LaunchConfigurationName=launch_configuration_id,
            MinSize=1,
            MaxSize=1,
            DesiredCapacity=1,
            VPCZoneIdentifier=subnet_ids,
            Tags=asg_tags
        )

        # Wait for ASG to be ready
        print("Waiting for ASG to be complete.")
        time.sleep(50)

        response = ASG_CLIENT.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
        print(response)

        # Get instance ID from ASG and wait for instance to be in ready state.
        instance_id = str(response['AutoScalingGroups'][0]['Instances'][0]['InstanceId'])
        ec2_waiter.wait(InstanceIds=[instance_id])

        return instance_id

    except ClientError as err:
        # Check if error code is due to throttling.
        if err.response['Error']['Code'] == 'Throttling':
            print("Throttling occurring.")
            raise MaskopyThrottlingException(err)
        print(f'Failed to create ASG with error: {err}')
        raise MaskopyResourceException(f'Failed to create ASG: {err}')

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
        raise MaskopyResourceException(f'Failed to create log group: {err}')

def create_task_definition(task_definition_name, task_definition_environment, image=None):
    """Function to create a task definition.
    Args:
        task_definition_name (str): The name of the cluster to create.
        task_definition_environment (:obj:`list` of :obj:`dict`):
            A list of dicts that contain the environment variables for task.
        image (str, optional): The name of the custom image to be used in task.
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
            executionRoleArn=f'arn:aws:iam::{account_id}:role/{service_role}'
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
