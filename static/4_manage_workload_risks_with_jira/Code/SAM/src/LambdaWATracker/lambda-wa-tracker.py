import boto3
import logging
import os
from jira import JIRA
import json
import hashlib
import re
from boto3.dynamodb.conditions import Key
from datetime import datetime, timezone
logger = logging.getLogger()
logger.setLevel(logging.INFO)

wa_client = boto3.client('wellarchitected')
ta_client = boto3.client('support')
ssm_client = boto3.client('ssm')
dynamodb_resource = boto3.resource('dynamodb')
sts_client = boto3.client('sts')
app_registry_client = boto3.client('servicecatalog-appregistry')

######################################
# Uncomment below for running on AWS Lambda
######################################
# TA integration on/off
TA_INTEGRATION = (os.environ['TA_INTEGRATION'] == 'True')

# Jira and OpsCenter integration on/off
OPS_CENTER_INTEGRATION = (os.environ['OPS_CENTER_INTEGRATION'] == 'True')
JIRA_INTEGRATION = (os.environ['JIRA_INTEGRATION'] == 'True')

# App Registry integration on/off
APP_REGISTRY_INTEGRATION = (os.environ['APP_REGISTRY_INTEGRATION'] == 'True')

# Workload related resources (based on tag)
TAG_KEY = os.environ['TAG_KEY']
TAG_VALUE = os.environ['TAG_VALUE']

# Scan all resources in region (Supported by AWS Resource Groups Tag Editor Tagging https://docs.aws.amazon.com/ARG/latest/userguide/supported-resources.html)
SCAN_ALL = (os.environ['SCAN_ALL'] == 'True')

# WA Implementation plan base-URL
WA_WEB_URL='https://docs.aws.amazon.com/wellarchitected/latest/framework/'
WA_WEB_ANCHOR='.html#implementation-guidance'

# Jira related variables
JIRA_URL = os.environ['JIRA_URL']
JIRA_USERNAME = os.environ['JIRA_USERNAME']
JIRA_SECRET_SSM_PARAM = os.environ['JIRA_SECRET_SSM_PARAM']
JIRA_PROJECT_KEY = os.environ['JIRA_PROJECT_KEY']

# DDB
DDB_TABLE = dynamodb_resource.Table(os.environ['DDB_TABLE'])

# Assumed Role Name
WORKLOAD_ACCOUNT_ROLE_NAME = os.environ['WORKLOAD_ACCOUNT_ROLE_NAME']

# List of TA Checks that are no specific to individual resources
NON_RESOURCE_SPECIFIC_TA_CHECKS = ['wuy7G1zxql']
######################################

# Assume Role of Workload Account
def assume_workload_account_role(account_id):
    workload_account_role = 'arn:aws:iam::' + account_id + ':role/' + WORKLOAD_ACCOUNT_ROLE_NAME
    assumed_role_credentials = sts_client.assume_role(
        RoleArn=workload_account_role,
        RoleSessionName='workload-account-role'
    )['Credentials']
    return assumed_role_credentials

# Function to query the dynamodb table
def ddb_query_entries(ticketHeaderKey):
    response = DDB_TABLE.query(
        KeyConditionExpression=Key('ticketHeaderKey').eq(ticketHeaderKey)
    )
    return response['Items']

# Function to add an entry to the dynamodb table
def ddb_put_entry(ticketId, ticketType, creationDate, updateDate, ticketHeaderKey, ticketContentKey, workloadId, lensAlias, questionId, bestPracticeId, workloadName, bestPracticeName, pillarId, pillarQuestion):
    response = DDB_TABLE.put_item(
       Item={
            'ticketId': ticketId,
            'ticketType': ticketType,
            'creationDate': creationDate,
            'updateDate': updateDate,
            'ticketHeaderKey': ticketHeaderKey,
            'ticketContentKey': ticketContentKey,
            'workloadId': workloadId,
            'lensAlias': lensAlias,
            'questionId': questionId,
            'bestPracticeId': bestPracticeId,
            'workloadName': workloadName,
            'bestPracticeName': bestPracticeName,
            'pillarId': pillarId,
            'pillarQuestion': pillarQuestion
        }
    )
    return response

# Function to update an entry in the dynamodb table
def ddb_update_entry(ticketHeaderKey, creationDate, updateDate, ticketContentKey):
    response = DDB_TABLE.update_item(
        Key={
            'ticketHeaderKey': ticketHeaderKey,
            'creationDate': creationDate
        },
        UpdateExpression="set #u=:u, #t=:t",
        ExpressionAttributeValues={
            ':u': updateDate,
            ':t': ticketContentKey
        },
        ExpressionAttributeNames={
            '#u': 'updateDate',
            '#t': 'ticketContentKey'
        },
        ReturnValues="UPDATED_NEW"
    )
    return response

def get_workload_resources(assumed_role_credentials, cfn_name = None):
    resources = {"resource_arns":[], "resource_names":[]}

    if APP_REGISTRY_INTEGRATION:
        if assumed_role_credentials != None:
            cloudformation_client = boto3.client(
                'cloudformation',
                aws_access_key_id=assumed_role_credentials['AccessKeyId'],
                aws_secret_access_key=assumed_role_credentials['SecretAccessKey'],
                aws_session_token=assumed_role_credentials['SessionToken']
            )
        else:
            cloudformation_client = boto3.client('cloudformation')
            resource_group_client_workload_account = boto3.client(
                'resourcegroupstaggingapi'
            )
        paginator = cloudformation_client.get_paginator('list_stack_resources')

        response_iterator = paginator.paginate(
            StackName=cfn_name
        )

        for page in response_iterator:
            for resource in page['StackResourceSummaries']:
                resources["resource_names"].append(resource['PhysicalResourceId'])

        return resources
    
    elif not APP_REGISTRY_INTEGRATION:
        if assumed_role_credentials != None:
            resource_group_client_workload_account = boto3.client(
                'resourcegroupstaggingapi',
                aws_access_key_id=assumed_role_credentials['AccessKeyId'],
                aws_secret_access_key=assumed_role_credentials['SecretAccessKey'],
                aws_session_token=assumed_role_credentials['SessionToken']
            )
        else:
            resource_group_client_workload_account = boto3.client(
                'resourcegroupstaggingapi'
            )
        paginator = resource_group_client_workload_account.get_paginator('get_resources')

        if SCAN_ALL:
            response_iterator = paginator.paginate()
        elif not SCAN_ALL:
            response_iterator = paginator.paginate(TagFilters=[
                    {
                        'Key': TAG_KEY,
                        'Values': [
                            TAG_VALUE,
                        ]
                    },
                ])

        for page in response_iterator:
            for resource in page['ResourceTagMappingList']:
                resources["resource_arns"].append(resource['ResourceARN'])
                resources["resource_names"].append(resource['ResourceARN'].split(':')[-1])

        return resources

def get_unselected_choices(answer):
    selected_choices = answer['SelectedChoices']

    all_choices = []
    for choice in answer['Choices']:
        all_choices.append({'choiceId': choice['ChoiceId'], 'title': choice['Title']})
    
    not_applicable_choices = []
    for choice in answer['ChoiceAnswers']:
        if choice['Status'] in ['NOT_APPLICABLE']:
            not_applicable_choices.append(choice['ChoiceId'])

    unselected_choices = [choice for choice in all_choices if choice['choiceId'] not in selected_choices + not_applicable_choices]
    none_of_these_selected = [choice for choice in all_choices if choice['title'] == 'None of these' and choice['choiceId'] in selected_choices]

    if len(none_of_these_selected) == 0:
        return unselected_choices
    else:
        return all_choices

def get_bp_ta_check_ids_list(check_details):
    bp_ta_check_ids_list = []
    for check in check_details['CheckDetails']:
        bp_ta_check_ids_list.append(check['Id'])
    return bp_ta_check_ids_list

def get_ta_check_summary(bp_ta_check_ids_list):
    bp_ta_checks = []
    ta_checks_list = ta_client.describe_trusted_advisor_checks(
        language='en'
    )['checks']

    filtered_ta_checks_list = [d for d in ta_checks_list if 'id' in d and d['id'] in bp_ta_check_ids_list]

    for check in filtered_ta_checks_list:
        ta_urls = [d for d in re.split('href="|" target=', check['description']) if d.startswith('https')]
        bp_ta_checks.append({'id': check['id'], 'name': check['name'], 'taRecommedationUrls': ta_urls, 'metadataOrder': check['metadata']})

    return bp_ta_checks

def get_index_value(metadata_list, workload_resources_list):
    for index, resource in enumerate(workload_resources_list):
        if resource in metadata_list:
            return index

def add_flagged_resources(bp_ta_checks, workload_resources, assumed_role_credentials = None, cfn_name = None):
    workload_resources = get_workload_resources(assumed_role_credentials, cfn_name)

    if assumed_role_credentials != None:
        ta_client_workload_account = boto3.client(
            'support',
            aws_access_key_id=assumed_role_credentials['AccessKeyId'],
            aws_secret_access_key=assumed_role_credentials['SecretAccessKey'],
            aws_session_token=assumed_role_credentials['SessionToken']
        )
    else:
        ta_client_workload_account = boto3.client(
            'support'
        )
    for check in bp_ta_checks:
        check['flaggedResources'] = []

        if not APP_REGISTRY_INTEGRATION:
            check['metadataOrder'].append('workloadResourceArn')

        # Retrieving results for the specific TA Check.
        check_result = ta_client_workload_account.describe_trusted_advisor_check_result(
            checkId=check['id'],
            language='en'
        )['result']

        # Adding only flagged resources related to the workload that are in 'warning' or 'error' TA status.
        if check_result['status'] in ['warning', 'error']:
            for flagged_resource in check_result['flaggedResources']:
                if flagged_resource['status'] in ['warning', 'error'] and check_result['checkId'] in NON_RESOURCE_SPECIFIC_TA_CHECKS:
                    check['flaggedResources'].append(flagged_resource)

                elif flagged_resource['status'] in ['warning', 'error'] and any(x in flagged_resource['metadata'] for x in workload_resources['resource_arns']):
                    resource_index = get_index_value(flagged_resource['metadata'], workload_resources['resource_arns'])
                    flagged_resource['metadata'].append(workload_resources['resource_arns'][resource_index])
                    check['flaggedResources'].append(flagged_resource)

                elif flagged_resource['status'] in ['warning', 'error'] and any(x in flagged_resource['metadata'] for x in workload_resources['resource_names']):
                    if not APP_REGISTRY_INTEGRATION:
                        resource_index = get_index_value(flagged_resource['metadata'], workload_resources['resource_names'])
                        flagged_resource['metadata'].append(workload_resources['resource_arns'][resource_index])
                    check['flaggedResources'].append(flagged_resource)
                    # Example of flagged_resource object
                    # {'status': 'warning', 'region': 'us-east-1', 'resourceId': 'ta-resource-id', 'isSuppressed': False, 'metadata': ['us-east-1', 'my-resource-name', 'Not enabled', 'No', 'Yellow', 'my-resource-arn']}

        # Example of check object
        # {'id': 'R365s2Qddf', 'name': 'Amazon S3 Bucket Versioning', 'taRecommedationUrls': ['https://docs.aws.amazon.com/AmazonS3/latest/dev/Versioning.html', ...], 'metadataOrder': ['Region', 'Bucket Name', 'Versioning', 'MFA Delete Enabled', 'Status', 'workloadResourceArn'], 'flaggedResources': [{'status': 'warning', 'region': 'us-east-1', 'resourceId': 'ta-resource-id', 'isSuppressed': False, 'metadata': ['us-east-1', 'my-resource-name', 'Not enabled', 'No', 'Yellow', 'my-resource-arn']}]}

    return(bp_ta_checks)

def flagged_resource_formatter(check_flagged):
    flagged_resources_list = []
    for resource in check_flagged['flaggedResources']:
        i = 0
        flagged_resource = {}
        for metadata_value in resource['metadata']:
            flagged_resource[check_flagged['metadataOrder'][i]] = metadata_value
            i+=1
        flagged_resources_list.append(flagged_resource)

    return (flagged_resources_list)

def create_ops_item(answer, choice, bp_ta_checks, WORKLOAD_ID, LENS_ALIAS, account_id, workload_name):
    # Filter out any TA Check for which there were no flagged resources.
    bp_ta_checks_flagged = [d for d in bp_ta_checks if len(d['flaggedResources']) > 0]

    # If there are any TA Check with flagged resources, proceed to create or update the OpsItem. If not omit the create/update.
    if len(bp_ta_checks_flagged) > 0:
        for check_flagged in bp_ta_checks_flagged:
            logger.info(f'Processing Best Practice: {choice["choiceId"]}, and Trusted Advisor check: {check_flagged["name"]}')

            imp_guid_web = WA_WEB_URL + choice['choiceId'] + WA_WEB_ANCHOR
            check_flagged['workloadId'] = WORKLOAD_ID
            check_flagged['pillarId'] = answer['PillarId'],
            check_flagged['questionTitle'] = answer['QuestionTitle']
            check_flagged['risk'] = answer['Risk']
            check_flagged['bestPracticeTitle'] = choice['title']
            check_flagged['implementationGuide'] = imp_guid_web
            flagged_resources_list = flagged_resource_formatter(check_flagged)

            ops_item_description = ("*AWS Account ID:* " + account_id + "\n*AWS Well-Architected related information:*\nWorkload Name: " + workload_name +
                "\nWorkload Id: " + WORKLOAD_ID +
                "\nPillar Id: " + answer['PillarId'] +
                "\nQuestion: " + answer['QuestionTitle'] +
                "\nQuestion Risk Identified: " + answer['Risk'] +
                "\nBest Practice: " + choice['title'] +
                "\n\n*AWS Trusted Advisor (TA) related information:*" + 
                "\nTA Check Id: " + check_flagged['id'] +
                "\nTA Check Name: " + check_flagged['name'] +
                "\n\n*Raw data with resources affected:*" + 
                "\nFlagged Resources (" + str(len(check_flagged['flaggedResources'])) + "):\n " + json.dumps(flagged_resources_list, indent = 3) + 
                "\n\n*Useful link for resolution:*" +
                "\nWell-Architected Implementation Guidance links:\n[" + imp_guid_web + "]" +
                "\n\nTrusted Advisor useful links:\n" + json.dumps(check_flagged['taRecommedationUrls'], indent = 3)
            )

            operation_data = []
            for resource in flagged_resources_list:
                if 'workloadResourceArn' in resource:
                    operation_data.append({'arn': resource['workloadResourceArn']})

            operational_data_object = {
                '/aws/resources': {
                    'Value': json.dumps(operation_data),
                    'Type': 'SearchableString'
                },
                'WorkloadId': {
                    'Value': WORKLOAD_ID,
                    'Type': 'SearchableString'
                },
                'BestPracticeId': {
                    'Value': choice['choiceId'],
                    'Type': 'SearchableString'
                },
                'Runbook': {
                    'Value': imp_guid_web,
                    'Type': 'SearchableString'
                }
            }

            ticketHeaderKey = hashlib.md5(('opscenter' + account_id + check_flagged['workloadId'] + check_flagged['bestPracticeTitle'] + check_flagged['id']).encode()).hexdigest()
            ticketContentKey = hashlib.md5(str(check_flagged).encode()).hexdigest()

            ddb_query_response = ddb_query_entries(ticketHeaderKey)
            
            # Verify in DDB table if the OpsItem was already created for this BP<-->TA Check pair.
            # If exist, check if affected resources or the question risk changed. If so, update the OpsItem and update entry in DDB.
            # If not exist, create the OpsItem and add new entry in DDB.
            if ddb_query_response:
                if ddb_query_response[0]['ticketContentKey'] != ticketContentKey:
                    logger.info(f'Either the number of affected resources or the question risk changed. Updating OpsItem issue: {ddb_query_response[0]["ticketId"]}')
                    update_ops_item_response = ssm_client.update_ops_item(
                        Description=(ops_item_description[:2020] + '..[Description truncated]') if len(ops_item_description) > 2020 else ops_item_description,
                        OperationalData=operational_data_object,
                        Title='[WALAB] [' + account_id + '] - ' + check_flagged['name'],
                        OpsItemId=ddb_query_response[0]['ticketId']
                    )
                    ddb_update_entry(ticketHeaderKey, ddb_query_response[0]['creationDate'], datetime.now(timezone.utc).isoformat(), ticketContentKey)
                else:
                    logger.info(f'No changes for OpsItem issue: {ddb_query_response[0]["ticketId"]}')
            else:
                logger.info('Creating OpsItem issue')
                create_ops_item_response = ssm_client.create_ops_item(
                    Description=(ops_item_description[:2020] + '..[Description truncated]') if len(ops_item_description) > 2020 else ops_item_description,
                    OperationalData=operational_data_object,
                    Source='wa_labs',
                    Title='[WALAB] [' + account_id + '] - ' + check_flagged['name']
                )
                ddb_put_entry(create_ops_item_response['OpsItemId'], 'opscenter', datetime.now(timezone.utc).isoformat(), '', ticketHeaderKey, ticketContentKey, check_flagged['workloadId'], LENS_ALIAS, answer['QuestionId'], choice['choiceId'], workload_name, choice['title'], answer['PillarId'], answer['QuestionTitle'])
                logger.info(f'OpsItem issue {create_ops_item_response["OpsItemId"]} created and recorded in DDB')
    else:
        logger.info(f'No flagged resources for this Best Practice {choice["choiceId"]} on any of its Trusted Advisor checks')


def create_ops_item_no_ta(answer, choice, WORKLOAD_ID, LENS_ALIAS, workload_arn, workload_name, lens_alias):

    logger.info(f'Processing Best Practice: {choice["choiceId"]}')

    account_id = workload_arn.split(':')[4]

    imp_guid_web = WA_WEB_URL + choice['choiceId'] + WA_WEB_ANCHOR
    wa_tool_console = 'https://' + workload_arn.split(':')[3] + '.console.aws.amazon.com/wellarchitected/home?region=' + workload_arn.split(':')[3] + '#/workload/' + WORKLOAD_ID + '/overview?owner=' + account_id
    wa_tool_question_console = 'https://' + workload_arn.split(':')[3] + '.console.aws.amazon.com/wellarchitected/home?region=' + workload_arn.split(':')[3] + '#/workload/' + WORKLOAD_ID + '/lens/' + lens_alias + '/pillar/' + answer['PillarId'] + '/question/' + answer['QuestionId'] + '?owner=' + account_id

    ops_item_description = ("*AWS Account ID:* " + account_id + "\n\n*Workload Name:* " + workload_name +
        "\n*Pillar Id:* " + answer['PillarId'] +
        "\n*Question:* " + answer['QuestionTitle'] +
        "\n*Question Risk Identified:* " + answer['Risk'] +
        "\n*Best Practice:* " + choice['title'] +
        "\n*Notes:*\n" + f"{answer['Notes'] if 'Notes' in answer else 'None'}" +
        "\n\n*Useful links*" +
        "\nBest Practice Implementation Guidance:\n[" + imp_guid_web + "]" +
        "\n\nAWS Well-Architected Tool console:\n[" + wa_tool_console + "]" +
        "\n\nAWS Well-Architected Tool Question console:\n[" + wa_tool_question_console + "]"
    )

    operation_data = [{'arn': workload_arn}]

    operational_data_object = {
        '/aws/resources': {
            'Value': json.dumps(operation_data),
            'Type': 'SearchableString'
        },
        'WorkloadName': {
            'Value': workload_name,
            'Type': 'SearchableString'
        },
        'WorkloadId': {
            'Value': WORKLOAD_ID,
            'Type': 'SearchableString'
        },
        'PillarId': {
            'Value': answer['PillarId'],
            'Type': 'SearchableString'
        },
        'Question': {
            'Value': answer['QuestionTitle'],
            'Type': 'SearchableString'
        },
        'QuestionRiskLevel': {
            'Value': answer['Risk'],
            'Type': 'SearchableString'
        },
        'BestPracticeId': {
            'Value': choice['choiceId'],
            'Type': 'SearchableString'
        },
        'BestPracticeNotFollowed': {
            'Value': choice['title'],
            'Type': 'SearchableString'
        },
        'BestPracticeImplementationGuidance': {
            'Value': imp_guid_web,
            'Type': 'SearchableString'
        }
    }

    ticketHeaderKey = hashlib.md5(('opscenter' + account_id + WORKLOAD_ID + choice['title']).encode()).hexdigest()
    ticketContentKey = hashlib.md5(str(ops_item_description).encode()).hexdigest()

    ddb_query_response = ddb_query_entries(ticketHeaderKey)
    
    # Verify in DDB table if the OpsItem was already created for this BP<-->TA Check pair.
    # If exist, check if affected resources or the question risk changed. If so, update the OpsItem and update entry in DDB.
    # If not exist, create the OpsItem and add new entry in DDB.
    if ddb_query_response:
        if ddb_query_response[0]['ticketContentKey'] != ticketContentKey:
            logger.info(f'Either the number of affected resources or the question risk changed. Updating OpsItem issue: {ddb_query_response[0]["ticketId"]}')
            update_ops_item_response = ssm_client.update_ops_item(
                Description=(ops_item_description[:2020] + '..[Description truncated]') if len(ops_item_description) > 2020 else ops_item_description,
                OperationalData=operational_data_object,
                Title='[WALAB] ' + '[' + answer['Risk'] + '] [' + workload_name + '] - ' + choice['title'],
                OpsItemId=ddb_query_response[0]['ticketId']
            )
            ddb_update_entry(ticketHeaderKey, ddb_query_response[0]['creationDate'], datetime.now(timezone.utc).isoformat(), ticketContentKey)
        else:
            logger.info(f'No changes for OpsItem issue: {ddb_query_response[0]["ticketId"]}')
    else:
        logger.info('Creating OpsItem issue')
        create_ops_item_response = ssm_client.create_ops_item(
            Description=(ops_item_description[:2020] + '..[Description truncated]') if len(ops_item_description) > 2020 else ops_item_description,
            OperationalData=operational_data_object,
            Source='well-architected-labs',
            Title='[WALAB] ' + '[' + answer['Risk'] + '] [' + workload_name + '] - ' + choice['title']
        )
        ddb_put_entry(create_ops_item_response['OpsItemId'], 'opscenter', datetime.now(timezone.utc).isoformat(), '', ticketHeaderKey, ticketContentKey, WORKLOAD_ID, LENS_ALIAS, answer['QuestionId'], choice['choiceId'], workload_name, choice['title'], answer['PillarId'], answer['QuestionTitle'])
        logger.info(f'OpsItem issue {create_ops_item_response["OpsItemId"]} created and recorded in DDB')


def create_jira_issue(jira_client, answer, choice, bp_ta_checks, WORKLOAD_ID, LENS_ALIAS, account_id, workload_name):

    # Filter out any TA Check for which there were no flagged resources.
    bp_ta_checks_flagged = [d for d in bp_ta_checks if len(d['flaggedResources']) > 0]

    # If there are any TA Check with flagged resources, proceed to create or update the Jira ticket. If not omit the create/update.
    if len(bp_ta_checks_flagged) > 0:
        for check_flagged in bp_ta_checks_flagged:
            logger.info(f'Processing Best Practice: {choice["choiceId"]}, and Trusted Advisor check: {check_flagged["name"]}')

            imp_guid_web = WA_WEB_URL + choice['choiceId'] + WA_WEB_ANCHOR
            check_flagged['workloadId'] = WORKLOAD_ID
            check_flagged['pillarId'] = answer['PillarId']
            check_flagged['questionTitle'] = answer['QuestionTitle']
            check_flagged['risk'] = answer['Risk']
            check_flagged['bestPracticeTitle'] = choice['title']
            check_flagged['implementationGuide'] = imp_guid_web
            flagged_resources_list = json.dumps(flagged_resource_formatter(check_flagged), indent = 3)

            jira_issue_description = ("*AWS Account ID:* " + account_id + "\n*AWS Well-Architected related information:*\nWorkload Name: " + workload_name +
                "\nWorkload Id: " + WORKLOAD_ID +
                "\nPillar Id: " + answer['PillarId'] +
                "\nQuestion: " + answer['QuestionTitle'] +
                "\nQuestion Risk Identified: " + answer['Risk'] +
                "\nBest Practice: " + choice['title'] +
                "\n\n*AWS Trusted Advisor (TA) related information:*" + 
                "\nTA Check Id: " + check_flagged['id'] +
                "\nTA Check Name: " + check_flagged['name'] +
                "\n\n*Raw data with resources affected:*" + 
                "\nFlagged Resources (" + str(len(check_flagged['flaggedResources'])) + "):\n{color:#97a0af} " + flagged_resources_list + "{color}" + 
                "\n\n*Useful link for resolution:*" +
                "\nWell-Architected Implementation Guidance links:\n[" + imp_guid_web + "]" +
                "\n\nTrusted Advisor useful links:\n" + json.dumps(check_flagged['taRecommedationUrls'], indent = 3)
            )
           
            ticketHeaderKey = hashlib.md5(('jira' + account_id + check_flagged['workloadId'] + check_flagged['bestPracticeTitle'] + check_flagged['id']).encode()).hexdigest()
            ticketContentKey = hashlib.md5(str(check_flagged).encode()).hexdigest()
            ddb_query_response = ddb_query_entries(ticketHeaderKey)
            
            # Verify in DDB table if the Jira ticket was already created for this BP<-->TA Check pair.
            # If exist, check if affected resources or the question risk changed. If so, update the Jira ticket and update entry in DDB.
            # If not exist, create the Jira ticket and add new entry in DDB.
            if ddb_query_response:
                if ddb_query_response[0]['ticketContentKey'] != ticketContentKey:
                    logger.info(f'Either the number of affected resources or the question risk changed. Updating JIRA issue: {ddb_query_response[0]["ticketId"]}')
                    jira_client.add_comment(ddb_query_response[0]['ticketId'], jira_issue_description)
                    ddb_update_entry(ticketHeaderKey, ddb_query_response[0]['creationDate'], datetime.now(timezone.utc).isoformat(), ticketContentKey)
                else:
                    logger.info(f'No changes for JIRA issue: {ddb_query_response[0]["ticketId"]}')
            else:
                logger.info('Creating JIRA issue')
                jira_create_issue_response = jira_client.create_issue(
                    project=JIRA_PROJECT_KEY,
                    summary='[WALAB] [' + account_id + '] - ' + check_flagged['name'],
                    description=jira_issue_description,
                    issuetype={'name': 'Task'}
                )
                ddb_put_entry(jira_create_issue_response.key, 'jira', datetime.now(timezone.utc).isoformat(), '', ticketHeaderKey, ticketContentKey, check_flagged['workloadId'], LENS_ALIAS, answer['QuestionId'], choice['choiceId'], workload_name, choice['title'], answer['PillarId'], answer['QuestionTitle'])
                logger.info(f'JIRA issue {jira_create_issue_response.key} created and recorded in DDB')
    else:
        logger.info(f'No flagged resources for this Best Practice {choice["choiceId"]} on any of its Trusted Advisor checks')


def create_jira_issue_no_ta(jira_client, answer, choice, WORKLOAD_ID, LENS_ALIAS, workload_arn, workload_name, lens_alias):

    logger.info(f'Processing Best Practice: {choice["choiceId"]}')

    account_id = workload_arn.split(':')[4]

    imp_guid_web = WA_WEB_URL + choice['choiceId'] + WA_WEB_ANCHOR
    wa_tool_console = 'https://' + workload_arn.split(':')[3] + '.console.aws.amazon.com/wellarchitected/home?region=' + workload_arn.split(':')[3] + '#/workload/' + WORKLOAD_ID + '/overview?owner=' + account_id
    wa_tool_question_console = 'https://' + workload_arn.split(':')[3] + '.console.aws.amazon.com/wellarchitected/home?region=' + workload_arn.split(':')[3] + '#/workload/' + WORKLOAD_ID + '/lens/' + lens_alias + '/pillar/' + answer['PillarId'] + '/question/' + answer['QuestionId'] + '?owner=' + account_id

    jira_issue_description = ("*AWS Account ID:* " + account_id + "\n\n*Workload Name:* " + workload_name +
        "\n*Pillar Id:* " + answer['PillarId'] +
        "\n*Question:* " + answer['QuestionTitle'] +
        "\n*Question Risk Identified:* " + answer['Risk'] +
        "\n*Best Practice:* " + choice['title'] +
        "\n*Notes:*\n" + f"{answer['Notes'] if 'Notes' in answer else 'None'}" +
        "\n\n*Useful links*" +
        "\nBest Practice Implementation Guidance:\n[" + imp_guid_web + "]" +
        "\n\nAWS Well-Architected Tool console:\n[" + wa_tool_console + "]" +
        "\n\nAWS Well-Architected Tool Question console:\n[" + wa_tool_question_console + "]"
    )
    
    ticketHeaderKey = hashlib.md5(('jira' + account_id + WORKLOAD_ID + choice['title']).encode()).hexdigest()
    ticketContentKey = hashlib.md5(str(jira_issue_description).encode()).hexdigest()
    ddb_query_response = ddb_query_entries(ticketHeaderKey)
    
    # Verify in DDB table if the Jira ticket was already created for this BP<-->TA Check pair.
    # If exist, check if affected resources or the question risk changed. If so, update the Jira ticket and update entry in DDB.
    # If not exist, create the Jira ticket and add new entry in DDB.
    if ddb_query_response:
        if ddb_query_response[0]['ticketContentKey'] != ticketContentKey:
            logger.info(f'Either the number of affected resources or the question risk changed. Updating JIRA issue: {ddb_query_response[0]["ticketId"]}')
            jira_client.add_comment(ddb_query_response[0]['ticketId'], jira_issue_description)
            ddb_update_entry(ticketHeaderKey, ddb_query_response[0]['creationDate'], datetime.now(timezone.utc).isoformat(), ticketContentKey)
        else:
            logger.info(f'No changes for JIRA issue: {ddb_query_response[0]["ticketId"]}')
    else:
        logger.info('Creating JIRA issue')
        jira_create_issue_response = jira_client.create_issue(
            project=JIRA_PROJECT_KEY,
            summary='[WALAB] ' + '[' + answer['Risk'] + '] [' + workload_name + '] - ' + choice['title'],
            description=jira_issue_description,
            issuetype={'name': 'Task'}
        )
        ddb_put_entry(jira_create_issue_response.key, 'jira', datetime.now(timezone.utc).isoformat(), '', ticketHeaderKey, ticketContentKey, WORKLOAD_ID, LENS_ALIAS, answer['QuestionId'], choice['choiceId'], workload_name, choice['title'], answer['PillarId'], answer['QuestionTitle'])
        logger.info(f'JIRA issue {jira_create_issue_response.key} created and recorded in DDB')

def collect_and_summit(bp_ta_check_ids_list, account_id, assumed_role_credentials, choice, answer, WORKLOAD_ID, LENS_ALIAS, workload_name, jira_client, cfn_name = None):
    # Creates initial schema list for all TA checks relevant to the BP.
    # E.g. [{'id': 'R365s2Qddf', 'name': 'Amazon S3 Bucket Versioning', 'taRecommedationUrls': ['https://docs.aws.amazon.com/.../'], 'metadataOrder': ['Region', 'Bucket Name']}]
    bp_ta_checks = get_ta_check_summary(bp_ta_check_ids_list)

    # Retrieving TA Check results and adding only the flagged resources related to the workload that are in 'warning' or 'error' TA status.
    add_flagged_resources(bp_ta_checks, account_id, assumed_role_credentials, cfn_name)

    # Proceed to create Jira tickets or OpsItems for each WA-BP<-->TA-Check unique pair (e.g. There can be 'n' TA Checks related to a WA BP, so it will create 'n' Jira/OpsItems for that BP).
    if choice['title'] != 'None of these':
        if OPS_CENTER_INTEGRATION:
            create_ops_item(answer, choice, bp_ta_checks, WORKLOAD_ID, LENS_ALIAS, account_id, workload_name)

        if JIRA_INTEGRATION:
            create_jira_issue(jira_client, answer, choice, bp_ta_checks, WORKLOAD_ID, LENS_ALIAS, account_id, workload_name)

def lambda_handler(event, context):
    if not OPS_CENTER_INTEGRATION and not JIRA_INTEGRATION:
        logger.info('No JIRA/OpsCenter integration enabled')
        return

    ######################################
    # Uncomment below for running on AWS Lambda
    ######################################
    WORKLOAD_ID=event['detail']['requestParameters']['WorkloadId']
    LENS_ALIAS=event['detail']['requestParameters']['LensAlias']
    LENS_ARN=event['detail']['responseElements']['LensArn']
    QUESTION_ID=event['detail']['requestParameters']['QuestionId']
    ######################################

    try:
        if JIRA_INTEGRATION:
            get_parameter_response = ssm_client.get_parameter(Name=JIRA_SECRET_SSM_PARAM,WithDecryption=True)
            jira_secret = str(get_parameter_response['Parameter']['Value'])
            jira_options = {'server': JIRA_URL}
            jira_client = JIRA(options=jira_options, basic_auth=(JIRA_USERNAME,jira_secret))

        workload_details = wa_client.get_workload(
            WorkloadId=WORKLOAD_ID
        )['Workload']

        workload_name = workload_details['WorkloadName']

        if TA_INTEGRATION:
            if 'AccountIds' not in workload_details and not APP_REGISTRY_INTEGRATION:
                logger.info(f'There are no Account IDs listed for this workload in the Well-Architected Tool. Specify at least one Account ID used by Trusted Advisor in the Well-Architected Tool workload Account IDs field. This field is required to activate Trusted Advisor. Exiting.')
                return
            elif 'AccountIds' in workload_details:
                account_ids = workload_details['AccountIds']

            if 'Applications' not in workload_details and APP_REGISTRY_INTEGRATION:
                logger.info(f'There are no AppRegistry "Applications" associated with this workload in the Well-Architected Tool, while the AppRegistry integration is enabled. Associate an AppRegistry application with this workload. This field is required to get resources related to the workload. Exiting.')
                return
            elif APP_REGISTRY_INTEGRATION:
                app_registry_application_arn = workload_details['Applications'][0]
                # Retrieve CFN stacks associated with the AppRegistry application
                app_registry_application_resources = app_registry_client.list_associated_resources(
                    application=app_registry_application_arn
                )['resources']

                # Get a list of only CFN_STACK names from app_registry_application_resources
                cfn_stack_arns = []
                for resource in app_registry_application_resources:
                    if resource['resourceType'] == 'CFN_STACK':
                        cfn_stack_arns.append(resource['arn'])

        # Retrieve WA Question answer details
        get_answer_response = wa_client.get_answer(
            WorkloadId=WORKLOAD_ID,
            LensAlias=LENS_ALIAS,
            QuestionId=QUESTION_ID
        )

        answer = get_answer_response['Answer']
        lens_alias = get_answer_response['LensAlias']

        if answer['Risk'] == 'UNANSWERED':
            logger.info(f'Question {answer["QuestionId"]} has not being answered. Skipping')
            return

        if not answer['IsApplicable']:
            logger.info(f'Question {QUESTION_ID} for Workload {WORKLOAD_ID} was marked as Not Applicable. Exiting.')
            return

        # Get list of unselected BPs (choices) for this question
        unselected_choices = get_unselected_choices(answer)
        
        # Loop through each unselected BPs (choices) for this question
        for choice in unselected_choices:

            if TA_INTEGRATION:
                # Get TA check details related to the WA BP (choice)
                check_details = wa_client.list_check_details(
                    WorkloadId=WORKLOAD_ID,
                    LensArn=LENS_ARN,
                    PillarId=answer['PillarId'],
                    QuestionId=QUESTION_ID,
                    ChoiceId=choice['choiceId']
                )

                # Get list of TA check Ids from here (e.g. ['opQPADkZvH', 'R365s2Qddf', 'H7IgTzjTYb']).
                bp_ta_check_ids_list = get_bp_ta_check_ids_list(check_details)

            if not TA_INTEGRATION:
                # Proceed to create Jira tickets or OpsItems for each WA-BP<-->TA-Check unique pair (e.g. There can be 'n' TA Checks related to a WA BP, so it will create 'n' Jira/OpsItems for that BP).
                if choice['title'] != 'None of these':
                    if OPS_CENTER_INTEGRATION:
                        create_ops_item_no_ta(answer, choice, WORKLOAD_ID, LENS_ALIAS, workload_details['WorkloadArn'], workload_name, lens_alias)

                    if JIRA_INTEGRATION:
                        create_jira_issue_no_ta(jira_client, answer, choice, WORKLOAD_ID, LENS_ALIAS, workload_details['WorkloadArn'], workload_name, lens_alias)

            elif APP_REGISTRY_INTEGRATION:
                # Loop through each of the CFN stacks listed for this workload in the AppRegistry
                for cfn_arn in cfn_stack_arns:
                    account_id = cfn_arn.split(':')[4]
                    logger.info(f'Processing Account: {account_id}')

                    # Only assume role for reviewing workload resources in other accounts
                    if account_id == sts_client.get_caller_identity().get('Account'):
                        assumed_role_credentials = None
                    else:
                        assumed_role_credentials = assume_workload_account_role(account_id)

                    cfn_name = cfn_arn.split(':')[-1].split('/')[-2]

                    if JIRA_INTEGRATION:
                        collect_and_summit(bp_ta_check_ids_list, account_id, assumed_role_credentials, choice, answer, WORKLOAD_ID, LENS_ALIAS, workload_name, jira_client, cfn_name)
                    elif not JIRA_INTEGRATION:
                        collect_and_summit(bp_ta_check_ids_list, account_id, assumed_role_credentials, choice, answer, WORKLOAD_ID, LENS_ALIAS, workload_name, None, cfn_name)

            elif not APP_REGISTRY_INTEGRATION:
                # Loop through each of the account ids listed for this workload in the WA Tool
                for account_id in account_ids:
                    logger.info(f'Processing Account: {account_id}')

                    # Only assume role for reviewing workload resources in other accounts
                    if account_id == sts_client.get_caller_identity().get('Account'):
                        assumed_role_credentials = None
                    else:
                        assumed_role_credentials = assume_workload_account_role(account_id)

                    if JIRA_INTEGRATION:
                        collect_and_summit(bp_ta_check_ids_list, account_id, assumed_role_credentials, choice, answer, WORKLOAD_ID, LENS_ALIAS, workload_name, jira_client)
                    elif not JIRA_INTEGRATION:
                        collect_and_summit(bp_ta_check_ids_list, account_id, assumed_role_credentials, choice, answer, WORKLOAD_ID, LENS_ALIAS, workload_name, None)

    except Exception as e:
        logger.error(f"Error encountered. Exception: {e}")
        raise e
