#
# Ensure all EC2 Instances that do not have an 'exempt' tag value set are attached to any security groups that are tagged 'mandatory'
# Description: Checks that all EC2 instances that have a certain tag format also have a specific security group
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

def is_applicable(instance_info):
    applicable = True

    if 'Tags' in instance_info:
        for tag in instance_info['Tags']:
            if tag['key'] == 'exempt' and tag['value'] == 'true':
                applicable = False

    return applicable

def evaluate_compliance(instanceId, instance_info):
    # Initialize evaluation to 'not applicable', i.e. rule doesn't apply
    compliant = False
    sec_group_ids = [s['GroupId'] for s in instance_info['SecurityGroups']]
    logger.info ("Instance {0} is a member of the security groups: {1}".format (instanceId, sec_group_ids))

    if set(mandatory_security_group_ids).issubset (set(sec_group_ids)):
        logger.info ("The instance {0} is a member of all mandatory security groups".format (instanceId))
        compliant = True
    else:
        logger.warn ("EC2 instance {0} is not compliant with mandatory security groups, attempting to remediate".format (instanceId))
        try:
            ec2_client.modify_instance_attribute (InstanceId = instanceId, Groups = list(set(sec_group_ids + mandatory_security_group_ids)))
            logger.info ("Successfully updated {0} security groups".format (instanceId))
            compliant = True
        except:
            logger.error ("Failed to remediate {0}: {1}".format (instanceId, sys.exc_info ()))

    return compliant

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
        ec2_client = boto3.client('ec2', region_name='ap-southeast-2')
        mandatory_security_group_ids = [s['GroupId'] for s in get_security_groups_by_tags (ec2_client, {'mandatory': 'true'})]

    logger.info ("Identified mandatory security groups: {0}".format (mandatory_security_group_ids))

    remediated = False
    remediation_required = True
    instanceId = event['detail']['instance-id']
    instance_info = ec2_client.describe_instances (InstanceIds = [instanceId])
    instance_info = instance_info['Reservations'][0]['Instances'][0]
    if instance_info['InstanceId'] != instanceId:
        return {"Error": "Instance {0} not found: {1}".format (instanceId, instance_info)}
    logger.info ("Retrieved details for instance: {0}".format (instance_info))

    if is_applicable(instance_info):
        logger.debug ("Evaluating compliance of resource")
        remediated = evaluate_compliance (instanceId, instance_info)
    else:
        remediation_required = False
        logger.info ("Config rule is not applicable to this resource")

    return {"instance": instanceId, "remediation_required": remediation_required, "remediated": remediated}
