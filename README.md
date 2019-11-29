<img src="./docs/images/maskopy-banner.png" alt="drawing" width="400px"/>

<br/>

Maskopy solution is to Copy and Obfuscate Production Data to Target Environments in AWS. 
It uses AWS Serverless services, Step functions, Lambda and Fargate.

<br/>

## Features:
### Simplified Copy and Obfuscation
Maskopy copies and provides ability to run obfuscation on production data across AWS accounts. Any sensitive information in the production data is obfuscated in a transient instance. The final obfuscated snapshot is shared in the user-specified environments.

### Self-Service and End-To-End Automated
Maskopy is a self-serviced solution that allows users to get production data without involving multiple teams. It is fully automated and is implemented to easily plug into CI/CD pipelines and other automation solutions through SNS or SQS.

### Secure Design
Maskopy has security controls such as access management via IAM roles, authorization on the caller identity, network access to transient resources controlled through security groups. Bring your own container with third party tools for obfuscation algorithms.

### Bring Your Own Obfuscation Container
Maskopy is a obfuscation tool agnostic solution. Teams can leverage any encryption tools or obfuscation frameworks based on their needs and bake those into a docker container. Bring the container to Maskopy solution  to run data obfuscation

## Documentation
- [Getting Started](docs/quickstart.md)
- [AWS Setup](docs/aws-setup.md)
- [Configurations](docs/configurations.md)
