#
# Ensure all EC2 Instances that do not have an 'exempt' tag value set are attached to any security groups that are tagged 'mandatory'
# Description: Checks that all EC2 instances that have a certain tag format also have a specific security group
#
# Trigger Type: Change Triggered
# Scope of Changes: EC2:Instance, EC2:SecurityGroup
# 

import logging
import boto3
import json
import sys

logger = logging.getLogger ('lambda.handler')
logger.setLevel (logging.INFO)

initialized = False
ec2_client = None
mandatory_security_group_ids = []

def is_applicable(config_item, event):
    status = config_item['configurationItemStatus']
    event_left_scope = event['eventLeftScope']
    applicable = ((status in ['OK', 'ResourceDiscovered']) and
            (event_left_scope == False) and
            (config_item['resourceType'] == 'AWS::EC2::Instance'))

    if applicable:
        for tag in config_item['configuration']['tags']:
            if tag['key'] == 'exempt' and tag['value'] == 'true':
                applicable = False

    return applicable

def evaluate_compliance(config_item, rule_parameters):
    # Initialize evaluation to 'not applicable', i.e. rule doesn't apply
    evaluation = 'NON_COMPLIANT'
    configuration = config_item['configuration']

    instanceId = configuration['instanceId']
    sec_group_ids = [s['groupId'] for s in configuration['securityGroups']]
    logger.info ("Instance {0} is a member of the security groups: {1}".format (instanceId, sec_group_ids))

    if set(mandatory_security_group_ids).issubset (set(sec_group_ids)):
        logger.info ("The instance {0} is a member of all mandatory security groups".format (instanceId))
        evaluation = 'COMPLIANT'
    else:
        logger.warn ("EC2 instance {0} is not compliant with mandatory security groups, attempting to remediate".format (instanceId))
        try:
            ec2_client.modify_instance_attribute (InstanceId = instanceId, Groups = list(set(sec_group_ids + mandatory_security_group_ids)))
            logger.info ("Successfully updated {0} security groups".format (instanceId))
            evaluation = 'COMPLIANT'
        except:
            logger.error ("Failed to remediate {0}: {1}".format (instanceId, sys.exc_info ()))

    return evaluation

def get_security_groups_by_tags (client, security_group_tags):
    filters = list()
    for key, value in security_group_tags.items():
        filters.extend(
            [
                {'Name': "tag-key", 'Values': [key]},
                {'Name': "tag-value", 'Values': [value]}
            ]
        )

    response = client.describe_security_groups(Filters=filters)

    return response['SecurityGroups']

def handler(event, context):
    global mandatory_security_group_ids, ec2_client

    logger.info ("Handling event: {0}".format (json.dumps(event)))

    if not initialized:
        logger.debug ('Initializing handler...')
        ec2_client = boto3.client('ec2')
        mandatory_security_group_ids = [s['GroupId'] for s in get_security_groups_by_tags (ec2_client, {'mandatory': 'true'})]

    logger.info ("Identified mandatory security groups: {0}".format (mandatory_security_group_ids))

    compliance_value = 'NOT_APPLICABLE'

    invoking_event = json.loads(event['invokingEvent'])
    logger.debug ("Invoking event: {0}".format (json.dumps (invoking_event)))
    rule_parameters = json.loads(event['ruleParameters'])

    if is_applicable(invoking_event['configurationItem'], event):
        logger.debug ("Evaluating compliance of resource")
        compliance_value = evaluate_compliance (invoking_event['configurationItem'], rule_parameters)
    else:
        logger.info ("Config rule is not applicable to this resource")

    config = boto3.client('config')
    evaluation = {
        'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
        'ComplianceResourceId': invoking_event['configurationItem']['resourceId'],
        'ComplianceType': compliance_value,
        'OrderingTimestamp': invoking_event['configurationItem']['configurationItemCaptureTime']
    }
    logger.info ("Returning evaluation {0}".format (evaluation))

    response = config.put_evaluations( Evaluations=[ evaluation ], ResultToken=event['resultToken'])
