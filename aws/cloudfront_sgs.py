'''
Copyright 2015 Amazon.com, Inc. or its affiliates. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License"). You may not use this file except in compliance with the License. A copy of the License is located at http://aws.amazon.com/apache2.0/
or in the "license" file accompanying this file. This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
'''

import sys
import boto3
import json
import urllib2

# Name of the service, as seen in the ip-groups.json file, to extract information for
SERVICE = "CLOUDFRONT"
# Ports your application uses that need inbound permissions from the service for
INGRESS_PORTS = [80]
# Tags which identify the security groups you want to update
SECURITY_GROUP_TAGS = {'Name': 'WebServerSG'}
# Max number of rules to add to a security group
MAX_RULES_PER_GROUP = 50

def get_ranges_for_service(ranges, service):
    """
    Loop thru the IP ranges and return the matching services
    """
    service_ranges = list()
    for prefix in ranges['prefixes']:
        if prefix['service'] == service:
            print 'Found ' + service + ' range: ' + prefix['ip_prefix']
            service_ranges.append(prefix['ip_prefix'])

    return service_ranges

def update_security_groups(new_ranges):
    """
    Update matching security groups with a list of ranges
    """
    client = boto3.client('ec2')

    groups = get_security_groups_for_update(client)
    print 'Found ' + str(len(groups)) + ' SecurityGroups to update'

    result = list()
    updated = 0

    for group in groups:
        if update_security_group(client, group, new_ranges):
            updated += 1
            result.append('Updated ' + group['GroupId'])

    result.append('Updated ' + str(updated) + ' of ' + str(len(groups)) + ' SecurityGroups')

    return result

def update_security_group(client, group, new_ranges):
    """
    Update security group with a list of ranges
    """
    added = 0
    removed = 0

    if 'IpPermissions' in group and len(group['IpPermissions']) > 0:
        for permission in group['IpPermissions']:
            if INGRESS_PORTS.count(permission['ToPort']) > 0:
                old_prefixes = list()
                to_revoke = list()
                to_add = list()
                for ip_range in permission['IpRanges']:
                    cidr = ip_range['CidrIp']
                    old_prefixes.append(cidr)
                    if new_ranges.count(cidr) == 0:
                        to_revoke.append(ip_range)
                        print group['GroupId'] + ": Revoking " + cidr + ":" + str(permission['ToPort'])

                for ip_range in new_ranges:
                    if old_prefixes.count(ip_range) == 0:
                        to_add.append({'CidrIp': ip_range})
                        print group['GroupId'] + ": Adding " + ip_range + ":" + str(permission['ToPort'])

                removed += revoke_permissions(client, group, permission, to_revoke)
                added += add_permissions(client, group, permission, to_add)
    else:
        for port in INGRESS_PORTS:
            to_add = list()
            for ip_range in new_ranges:
                to_add.append({'CidrIp': ip_range})
                print group['GroupId'] + ": Adding " + ip_range + ":" + str(port)
            permission = {'ToPort': port, 'FromPort': port, 'IpProtocol': 'tcp'}
            added += add_permissions(client, group, permission, to_add)

    print group['GroupId'] + ": Added " + str(added) + ", Revoked " + str(removed)
    return added > 0 or removed > 0

def revoke_permissions(client, group, permission, to_revoke):
    """
    Revoke a rule from a security group
    """
    if len(to_revoke) > 0:
        revoke_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_revoke,
            'IpProtocol': permission['IpProtocol']
        }

        client.revoke_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[revoke_params])

    return len(to_revoke)


def add_permissions(client, group, permission, to_add):
    """
    Add a rule to a security group
    """
    if len(to_add) > 0:
        add_params = {
            'ToPort': permission['ToPort'],
            'FromPort': permission['FromPort'],
            'IpRanges': to_add,
            'IpProtocol': permission['IpProtocol']
        }

        client.authorize_security_group_ingress(GroupId=group['GroupId'], IpPermissions=[add_params])

    return len(to_add)

def get_security_groups_for_update(client):
    """
    Return a list of matching security groups
    """
    filters = []
    for key, value in SECURITY_GROUP_TAGS.iteritems():
        filters.extend(
            [
                {'Name': "tag-key", 'Values': [key]},
                {'Name': "tag-value", 'Values': [value]}
            ]
        )

    response = client.describe_security_groups(Filters=filters)

    return response['SecurityGroups']

def get_ip_groups_json(url):
    """
    Return the HTTP response from URL
    """
    print "Updating from " + url

    response = urllib2.urlopen(url)
    ip_json = response.read()

    return ip_json

def create_ranges_groups(ranges, vpc_id):
    """
    Create 1 or more groups to hold the ranges
    """
    client = boto3.client('ec2')
    prefix = SERVICE + "-only-"
    description = SERVICE + " only"
    i = 1
    remainder = list(ranges)
    groups = []

    while remainder:
        head = remainder[:MAX_RULES_PER_GROUP]
        remainder = remainder[MAX_RULES_PER_GROUP:]
        group_name = prefix + str(i)

        all_groups = client.describe_security_groups()
        filter_groups = [ sg for sg in all_groups['SecurityGroups'] if sg['GroupName'] == group_name ]
        if filter_groups:
            print("Existing security group: %s" % group_name)
            update_group = filter_groups[0]
        else:
            print("Creating security group: %s" % group_name)
            update_group = client.create_security_group(
                Description=description,
                GroupName=group_name,
                VpcId=vpc_id
            )
        groups.append(update_group['GroupId'])
        if update_security_group(client, update_group, head):
            print('Updated ' + update_group['GroupId'])
        i += 1
    return groups


def main():
    """
    Retrieve AWS IP Address Ranges https://docs.aws.amazon.com/general/latest/gr/aws-ip-ranges.html
    Update matching security groups with the SERVICE ranges
    """
    ip_ranges = json.loads(get_ip_groups_json('https://ip-ranges.amazonaws.com/ip-ranges.json'))

    # extract the service ranges
    cf_ranges = get_ranges_for_service(ip_ranges, SERVICE)

    # Clean out the matching security groups
    result = update_security_groups([])
    print "\n".join(result)


    try:
        response = urllib2.urlopen("http://169.254.169.254/latest/meta-data/instance-id", timeout=5)
        instance_id = response.read()
    except:
        print("Not running on an instance")
        sys.exit(0)

    client = boto3.client('ec2')
    sgs = client.describe_instances(
        InstanceIds = [ instance_id ]
    )
    vpc_id = sgs['Reservations'][0]['Instances'][0]["VpcId"]
    current_sgs = [sg['GroupId'] for sg in sgs['Reservations'][0]['Instances'][0]["SecurityGroups"] ]

    # create new groups that lock down to SERVICE
    new_sgs = create_ranges_groups(cf_ranges, vpc_id)
    union_sgs = list(set().union(current_sgs, new_sgs))
    # update the instance security groups
    print("Updating security group on: %s -> %s" % (instance_id, " ".join(union_sgs)))
    client.modify_instance_attribute(
        InstanceId=instance_id,
        Groups=union_sgs
    )

if __name__ == "__main__":
    main()
