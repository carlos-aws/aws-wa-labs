#!/bin/bash

AWS_REGION=$(curl --silent http://169.254.169.254/latest/dynamic/instance-identity/document | jq '.region' | sed -e 's/^"//' -e 's/"$//')
CFN_CONSOLE="https://$AWS_REGION.console.aws.amazon.com/cloudformation/home?region=$AWS_REGION"

echo -e '\n##############################'
echo 'Deleting SAM Stack'
echo '##############################'

cd ~/environment/aws-well-architected-labs/static/watool/200_Accelerating_Well_Architected_Framework_Reviews_using_integrated_AWS_Trusted_Advisor_insights/Code/SAM/

sam delete --stack-name well-architected-tool-ta-jira-lab-sam --no-prompts --region $AWS_REGION

echo -e '\n##############################'
echo 'Deleting System Manager Parameter'
echo '##############################'

aws ssm delete-parameter --name walabjirasecret

echo -e '\n##############################'
echo 'Deleting Cloud9 Environment (You will get logged out of this IDE session)'
echo '##############################'

aws cloudformation delete-stack --stack-name well-architected-tool-ta-jira-lab-cloud9

echo -e '\n##############################'
echo 'Go to the CloudFormation console and verify that the Cloud9 stack "well-architected-tool-ta-jira-lab-cloud9" is being deleted:'
echo $CFN_CONSOLE
echo -e '\nYou can close this browser windows now'
echo '##############################'

