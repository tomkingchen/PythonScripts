#!/usr/local/bin/python3

import json
import boto3

#Explicitly declaring variables here grants them global scope
cidr_block = ""
ip_protpcol = ""
from_port = ""
to_port = ""
from_source = ""
is_bad = False
vm_sg_set = set()

for region in ["ap-southeast-2","ap-southeast-1"]:
    ec2=boto3.client('ec2', region )
    all_instances = ec2.describe_instances()
    sgs = ec2.describe_security_groups()["SecurityGroups"]
    #Get security groups in use
    for reservation in all_instances["Reservations"]:
        for instance in reservation["Instances"]:
            for vm_sg in instance["SecurityGroups"]:
                vm_sg_set.add(vm_sg["GroupName"])
    
    #Get security group with allow any IP inbound rules
    for sg in sgs:
        group_name = sg['GroupName']
        group_id = sg['GroupId']
        # InBound permissions ##########################################
        inbound = sg['IpPermissions']
	for rule in inbound:
            #Is source/target an IP v4?
            if len(rule['IpRanges']) > 0:
            	for ip_range in rule['IpRanges']:
                	if ip_range['CidrIp'] == "0.0.0.0/0":
                    	    is_bad = True	

            #Is source/target an IP v6?
            if len(rule['Ipv6Ranges']) > 0:
            	for ip_range in rule['Ipv6Ranges']:
                	if ip_range['CidrIpv6'] == "::/0":
                            is_bad = True
                            
        if is_bad:
            if group_name in vm_sg_set:
                print("%s,%s,inUse" % (group_name,group_id))
                is_bad = False
            else:
                print("%s,%s,NotInUse" % (group_name,group_id))
                is_bad = False
                
