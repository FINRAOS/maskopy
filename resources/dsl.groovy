// a Jenkins jobDSL script to generate the test jobs

String path = 'MYSTIFY/MASKOPY'
folder(path)

job(path + '/maskopy-trigger') {
    parameters {
        stringParam{
            name('STEP_FN_ARN')
            defaultValue('')
            description('The step function arn.')
            trim(true)
        }
        stringParam{
            name('APPLICATION_NAME')
            defaultValue('')
            description('The application name.')
            trim(true)
        }
        stringParam{
            name('DESTINATION_ENV')
            defaultValue('')
            description('The destination environment.')
            trim(true)
        }
        stringParam{
            name('COST_CENTER')
            defaultValue('')
            description('The cost center to be used.')
            trim(true)
        }
        stringParam{
            name('CUSTOM_TASK_IMAGE')
            defaultValue('')
            description('The custom image to be used.')
            trim(true)
        }
        stringParam{
            name('RDS_FINAL_SNAPSHOT_IDENTIFIER')
            defaultValue('')
            description('Enter RDS parameter group name.')
            trim(true)
        }
        stringParam{
            name('RDS_SNAPSHOT_IDENTIFIER')
            defaultValue('')
            description('Enter original snapshot id from source environment.')
            trim(true)
        }
        stringParam{
            name('RDS_INSTANCE_TYPE')
            defaultValue('')
            description('Enter RDS instance type.')
            trim(true)
        }
        stringParam{
            name('RDS_PARAMETER_GROUP')
            defaultValue('')
            description('Enter RDS parameter group name.')
            trim(true)
        }
        stringParam{
            name('OBFUSCATE_RUN_MODE')
            defaultValue('')
            description('Enter obfuscation run mode: fargate, ecs, or none.')
            trim(true)
        }
        stringParam{
            name('OBFUSCATION_SCRIPT_PATH')
            defaultValue('')
            description('Enter S3 bucket path that obfuscation script is located.')
            trim(true)
        }
    }
    scm {
        git {
            remote {
                url('ssh://git@bitbucket.finra.org:7999/mystify/maskopy-os.git')
                credentials('4bdb84e3-adf3-4eee-bf07-074621fc513c')
            }
            branch('master')
        }
    }
    environmentVariables(AWS_DEFAULT_REGION: 'us-east-1')
    steps {
        // test that the job was run
        shell("""#!/bin/bash -e
bash maskopy.sh""")
    }
}
