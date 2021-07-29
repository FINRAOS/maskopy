# AWS IAM Roles Setup
AWS IAM role is required to run the Maskopy solution's Step functions, Lambda and Fargate tasks. Since Maskopy needs to access resources like RDS snapshots from a source account that is different than its current account, it needs Cross account access.
We will look at how to setup these IAM roles in the source and staging accounts.
Make a note of the account IDs for Source and staging accounts since they will be used in the IAM roles.

## IAM Roles

### Source Account
Create the Cross-Account role, `XACNT_MASKOPY` in the **Source Account** to share and copy snapshots from Source Account to Staging Account. The purpose of this role is to copy RDS snapshots to share with the staging account. It also require delete permissions on RDS snapshots to cleanup the transient snapshot copies that were made during the maskopy execution. The delete permission is limited to only RDS snapshots with the prefix *maskopy*. This ensures that this role allows maskopy to delete only the snapshots that are created by maskopy.

Replace \<STAGING-ACCOUNT> with staging account number. Replace \<SOURCING-ACCOUNT> with source account number.

#### IAM role

```json
{
       "Version": "2012-10-17",
       "Statement": [
           {
               "Sid": "KMSandLogs",
               "Effect": "Allow",
               "Action": [
                   "logs:CreateLogStream",
                   "kms:List*",
                   "kms:Get*",
                   "kms:CreateAlias",
                   "kms:Describe*",
                   "kms:CreateKey",
                   "kms:CreateGrant",
                   "logs:CreateLogGroup",
                   "logs:PutLogEvents",
                   "kms:ReEncrypt*"
               ],
               "Resource": "*"
           },
           {
               "Sid": "RDSSnapshotPolicy",
               "Effect": "Allow",
               "Action": [
                   "rds:ListTagsForResource",
                   "rds:DescribeDBClusterSnapshots",
                   "rds:DescribeDBSnapshots",
                   "rds:CopyDBClusterSnapshot",
                   "rds:CopyDBSnapshot",
                   "rds:ModifyDBClusterSnapshotAttribute",
                   "rds:ModifyDBSnapshotAttribute"
               ],
               "Resource": "arn:aws:rds:*:<SOURCE-ACCOUNT>:*:*"
           },
           {
               "Sid": "RDSDeletePolicy",
               "Effect": "Allow",
               "Action": [
                   "rds:DeleteDBSnapshot"
               ],
               "Resource": "arn:aws:rds:*:<SOURCE-ACCOUNT>:*:maskopy*"
           }
       ]
 }
```

###  Staging account

#### Lambda and Step function role
Create an IAM role - `LAMBDA_MASKOPY` for Maskopy's Lambda and Step function. This role will be created in the staging account.

Add below AWS Managed policy for Lambda
 - `AWSLambdaExecute`
 - `AWSLambdaRole`
 - Below is a custom policy that is required to access other services such as ECS/Fargate, KMS, RDS.

Replace \<STAGING-ACCOUNT> with staging account number. Replace \<SOURCING-ACCOUNT> with source account number.

```json
{
 "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "MultiplePolicy",
            "Effect": "Allow",
            "Action": [
                "events:Put*",
                "events:DescribeRule",
                "rds:DescribeDBSnapshots",
                "rds:DescribeDBClusterSnapshots",
                "ecs:CreateCluster",
                "ec2:DeleteNetworkInterface",
                "rds:DescribeDBParameterGroups",
                "s3:ListBucket",
                "ecs:DeregisterTaskDefinition",
                "ec2:CreateNetworkInterface",
                "ec2:DescribeNetworkInterfaces",
                "ecs:RegisterTaskDefinition",
                "rds:DescribeDBClusters",
                "rds:DescribeDBInstances",
                "rds:DescribeOptionGroups"
            ],
            "Resource": "*"
        },
        {
            "Sid": "RDSPolicy",
            "Effect": "Allow",
            "Action": [
                "rds:CreateDBSnapshot",
                "rds:CreateDBClusterSnapshot",
                "rds:RestoreDBInstanceFromDBSnapshot",
                "rds:RestoreDBClusterFromSnapshot"
            ],
            "Resource": [
                "arn:aws:rds:*:*:*:*maskopy*",
                "arn:aws:rds:*:*:*:default*"
            ]
        },
        {
            "Sid": "PassRolePolicy",
            "Effect": "Allow",
            "Action": "iam:PassRole",
            "Resource": "arn:aws:iam::<STAGING-ACCOUNT>:role/*MASKOPY*"
        },
        {
            "Sid": "RDSMaskopyPolicy",
            "Effect": "Allow",
            "Action": "rds:*",
            "Resource": [
                "arn:aws:rds:*:*:db:maskopy*",
                "arn:aws:rds:*:*:snapshot:*maskopy*"
            ]
        }
    ]
}
```

##### Updates to Lambda Role after KMS Keys are created
Skip this step if you have not created KMS Keys in Source account. KMS keys creation is described here.
Once the KMS keys are created in the Source account, Note the KMS Key ID. It needs to be replaced in the below Policy.
Also replace Source account, staging account, Staging-DefaultRDSKMSKeyID.

Update the LAMBDA_MASKOPY IAM role and Add below policy.

Replace \<STAGING-ACCOUNT> with staging account number. Replace \<SOURCING-ACCOUNT> with source account number.

```json
        {
            "Sid": "KMSPolicy",
            "Effect": "Allow",
            "Action": [
                "kms:RevokeGrant",
                "kms:CreateGrant",
                "kms:ListGrants"
            ],
            "Resource": [
                "arn:aws:kms:us-east-1:<STAGING-ACCOUNT>:key/<STAGING-DefaultRDSKMSKey>",
                "arn:aws:kms:us-east-1:<SOURCE-ACCOUNT>:key/<SOURCE-KMSKeyID>"
            ],
            "Condition": {
                "Bool": {
                    "kms:GrantIsForAWSResource": "true"
                }
            }
        },
         {
            "Sid": "MaskopyLambdaPolicy",
            "Effect": "Allow",
            "Action": [
                "sts:AssumeRole",
                "kms:Decrypt",
                "ecs:RunTask",
                "kms:Encrypt",
                "sqs:SendMessage",
                "kms:DescribeKey",
                "ecs:StartTask",
                "ecs:DeleteCluster",
                "kms:RetireGrant",
                "ecs:DescribeTasks",
                "ecs:DescribeClusters"
            ],
            "Resource": [
                "arn:aws:iam::*:role/Xacnt_MASKOPY",
                "arn:aws:kms:us-east-1:<STAGING-ACCOUNT>:key/<STAGING-DefaultRDSKMSKey>",
                "arn:aws:kms:us-east-1:<SOURCE-ACCOUNT>:key/<SOURCE-KMSKeyID>",
                "arn:aws:ecs:*:<STAGING-ACCOUNT>:task-definition/*:*",
                "arn:aws:ecs:*:<STAGING-ACCOUNT>:cluster/*",
                "arn:aws:ecs:*:<STAGING-ACCOUNT>:task/*",
                "arn:aws:sqs:*:*:*"
            ]
        }
```

#### Fargate service role

This IAM role - `ECS_MASKOPY` is the service role that is applied to the Fargate tasks created by maskopy.

1. Attach the `AmazonEC2ContainerServiceRole` AWS managed policy to this role to allow access to ECS and Fargate resources.
2. Below is the custom policy that needs to be applied to the Fargate service role in order to access to ECR, S3, logs and RDS.

Access to ECR needed to pull the docker images from ECR. Access to S3 is needed to pull the obfuscation scripts from S3.
Access to RDS is required to access and update RDS instances during the obfuscation process.

Replace \<STAGING-ACCOUNT> with staging account number. Replace \<RDS-DEFAULTKMSKEYID> with the RDS Default KMS KeyID

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "ecr:DescribeImages",
                "s3:Get*",
                "ecr:GetAuthorizationToken",
                "ecr:DescribeRepositories",
                "ecr:ListTagsForResource",
                "ecr:ListImages",
                "s3:List*",
                "ecr:GetRepositoryPolicy"
            ],
            "Resource": "*"
        },
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "arn:aws:logs:*:*:*"
        },
        {
            "Sid": "RDSPolicy",
            "Effect": "Allow",
            "Action": [
                "rds:DescribeDBSnapshots",
                "rds:DescribeDBClusterSnapshots",
                "rds:CopyDBSnapshot",
                "rds:CopyDBClusterSnapshot",
                "rds:DescribeDBInstances",
                "rds:DescribeDBClusters",
                "rds:ModifyDBInstance",
                "rds:ModifyDBCluster",
                "rds:ModifyDBSnapshotAttribute",
                "rds:ModifyDBClusterSnapshotAttribute"
            ],
            "Resource": "arn:aws:rds:*:*:*:maskopy*"
        },
        {
            "Sid": "KMSPolicy",
            "Effect": "Allow",
            "Action": [
                "kms:EnableKey",
                "kms:Decrypt",
                "kms:ReEncryptFrom",
                "kms:ReEncrypt*",
                "kms:GenerateDataKey*",
                "kms:ListKeys",
                "kms:Encrypt",
                "kms:ReEncryptTo",
                "kms:DescribeKey",
                "kms:CreateGrant"
            ],
            "Resource": "arn:aws:kms:us-east-1:<STAGING-ACCOUNT>:key/<RDS-DEFAULTKMSKeyID>"
        }
    ]
}
```

## Trust Relationship

### Source Account

#### Trust Relationship for Cross Account Role in Source Account

XACNT_MASKOPY role needs to have the trust relationship with the Maskopy's Lambda role that is running in the Staging account. Maskopy's execution role (Lambda) assumes this Cross account role created above to access resources in the source account.
Here is the trust relationship policy.

Replace \<STAGING-ACCOUNT> with staging account number. Replace \<SOURCING-ACCOUNT> with source account number.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::<STAGING-ACCOUNT>:role/LAMBDA_MASKOPY"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```


#### Trust Relationship for Lambda role

Trust relationship for the Lambda and step function role (LAMBDA_MASKOPY) needs to allow access to `states`, `events`, `lambda`, `sts` services

```json
{
     "Version": "2012-10-17",
     "Statement": [
       {
         "Sid": "",
         "Effect": "Allow",
         "Principal": {
           "Service": [
             "lambda.amazonaws.com",
             "states.us-east-1.amazonaws.com",
             "states.us-east-2.amazonaws.com",
             "states.us-west-1.amazonaws.com",
             "sts.amazonaws.com",
             "states.us-west-2.amazonaws.com",
             "states.amazonaws.com",
             "events.amazonaws.com"
           ]
         },
         "Action": "sts:AssumeRole"
       }
     ]
}
```

#### Trust Relationship for ECS Service role
Apply this trust relationship for ECS_MASKOPY role.
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```


## Destination Account
In the current release of Maskopy, the destination account and Staging account is the same.  In upcoming releases, maskopy will run in staging account and share snapshots to the destination account. It requires IAM role updates and a minor enhancement to the orchestration.
### Maskopy Invoker Role
Each Application onboarding to Maskopy should create an IAM role that allows access to invoke and use Maskopy solution. Add the `Application_Name` in the IAM role.
Each application leveraging Maskopy will be using the Invoker IAM role to authorize itself. Maskopy checks that the caller IAM role name contains the application name. So, if Application, FooBar wants to use Maskopy, it would require an IAM role named Foobar_invoker or Maskopy_Foobar to be able to invoke Maskopy.

See below the policy that is required for the Maskopy Invoker Role.

Replace \<ACCOUNT> with staging account number.

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "MaskopyPolicy",
            "Effect": "Allow",
            "Action": "states:StartExecution",
            "Resource": [
                "arn:aws:states:*:<ACCOUNT>:stateMachine:maskopy*",
                "arn:aws:states:*:<ACCOUNT>:stateMachine:MASKOPY*"
            ]
        }
    ]
}
```

