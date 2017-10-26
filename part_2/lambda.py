'''
Copyright 2016 Amazon.com, Inc. or its affiliates. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at
    http://aws.amazon.com/apache2.0/
or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
'''
import logging
import boto3
from botocore.exceptions import ClientError
import hashlib
import json
import urllib

logger = logging.getLogger('lambda.handler')
logger.setLevel(logging.INFO)

SERVICES = ('AMAZON', 'EC2')
REGIONS = ('GLOBAL', 'eu-west-1')


def handler(event, context):
    logger.info("Received event: " + json.dumps(event, indent=2))
    message = json.loads(event['Records'][0]['Sns']['Message'])

    # Load the ip ranges from the url
    ip_ranges = json.loads(get_ip_groups_json(message['url'], message['md5']))

    # extract the service ranges from ip_ranges, map them by region and then service (region -> service -> ranges)
    service_ranges = get_ranges_for_services(ip_ranges, SERVICES, REGIONS)

    # update the security groups
    result = {'updated_security_groups': []}
    client = boto3.client('ec2', region_name='eu-west-1')
    for region in REGIONS:
        for service in service_ranges[region]:
            groups = get_security_groups_for_update (client, {'managed': 'true', 'region': region.lower(), 'service': service.lower()})

            for group in groups:
                try:
                    logger.debug ("Updating group: {0}".format (group))
                    update_security_group (client, group, service_ranges[region][service], 443)
                    result['updated_security_groups'].append(group['GroupId'])
                    logger.info ("Updated security group {0} ({1})".format(group['GroupName'], group['GroupId']))
                except ClientError as client_error:
                    logger.error("Error updating {0}: {1}".format (group['GroupId'], client_error))

    return result


def get_ip_groups_json(url, expected_hash):
    logger.info("Retrieving updated IP ranges from {0}".format (url))

    response = urllib.request.urlopen(url)
    ip_json = response.read()

    m = hashlib.md5()
    m.update(ip_json)
    hash = m.hexdigest()

    if hash != expected_hash:
        raise Exception('MD5 Mismatch: got ' + hash + ' expected ' + expected_hash)

    return ip_json


def get_ranges_for_services(ranges, services, regions):
    service_ranges = {}
    for region in regions:
        service_ranges[region] = {}

        for service in services:
            service_ranges[region][service] = []

            for prefix in ranges['prefixes']:
                if prefix['service'] == service and prefix['region'] == region:
                    logger.debug('Found ' + service + ' range: ' + prefix['ip_prefix'])
                    if prefix['ip_prefix'] not in service_ranges[region][service]:
                        logger.debug("Storing {0}".format(prefix['ip_prefix']))
                        service_ranges[region][service].append(
                            prefix['ip_prefix'])

    for region in [r for r in service_ranges if r != 'GLOBAL']:
        service_ranges[region]['AMAZON'] = list(
            set(service_ranges[region]['AMAZON']) - set(service_ranges[region]['EC2']))

    for region in service_ranges:
        for service in service_ranges[region]:
            logger.info("Region {0}, service {1} has {2} CIDR ranges".format (region, service, len(service_ranges[region][service])))

    return service_ranges


def update_security_group(client, group, new_ranges, port):
    added = 0
    removed = 0
    permission = {'ToPort': port, 'FromPort': port, 'IpProtocol': 'tcp'}

    old_ranges = []
    for permission in group['IpPermissionsEgress']:
        if 'IpRanges' in permission:
            old_ranges += [r['CidrIp'] for r in permission['IpRanges']]

    to_revoke = list(set(old_ranges) - set(new_ranges))
    to_add = list(set(new_ranges) - set(old_ranges))
    logger.debug ("Will add {0} rules and revoke {1} rules to {0} ({1})".format ( len(to_add), len(to_revoke), group['GroupName'], group['GroupId']))

    removed += revoke_permissions(client, group, permission, to_revoke)
    added += add_permissions(client, group, permission, to_add)

    logger.info ("{0} ({1}): Added {2}, Revoked {3}".format (group['GroupName'], group['GroupId'], added, removed))
    return (added > 0 or removed > 0)


def revoke_permissions(client, group, permission, to_revoke):
    ip_ranges = [{'CidrIp': r} for r in to_revoke]
    if len(to_revoke) > 0:
        revoke_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': ip_ranges,
            'IpProtocol': permission['IpProtocol']
        }

        client.revoke_security_group_egress(
            GroupId=group['GroupId'], IpPermissions=[revoke_params])

    return len(to_revoke)


def add_permissions(client, group, permission, to_add):
    logger.debug("Adding permission to Cidr range: {0}".format(to_add))

    ip_ranges = [{'CidrIp': r} for r in to_add]
    if len(to_add) > 0:
        add_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': ip_ranges,
            'IpProtocol': permission['IpProtocol']
        }

        client.authorize_security_group_egress(
            GroupId=group['GroupId'], IpPermissions=[add_params])

    return len(to_add)


def get_security_groups_for_update(client, security_group_tag):
    filters = list()
    for key, value in security_group_tag.items():
        filters.extend(
            [
                {'Name': "tag-key", 'Values': [key]},
                {'Name': "tag-value", 'Values': [value]}
            ]
        )

    response = client.describe_security_groups(Filters=filters)

    return response['SecurityGroups']
