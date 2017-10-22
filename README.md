This workshop was originally created in October of 2017 in support of getting LSEG engaged in governance and using the tools available to them in AWS.

The workshop is intended to be conducted with audience participation in approximately 90 minutes.

The workshop is broken up into 3 parts, the 3rd of which is optional.

## simple demonstration of security groups and the CLI ability to view and modify AWS resources
Part 1:
- Via the console create a security group that permits SSH ingress with no egress (ssh-sg) 
  
  - EC2 > Security Groups > Create Security Group
  - Remove egress permissions, permit SSH ingress
- Via the console create a security group that permits egress out to httpbin.org only (httpbin-access-sg)
  
  - EC2 > Security Groups > Create Security Group
  - Permit traffic to port 80 to 50.19.253.166/32
- Via the console create an EC2 instance with only the ssh-sg group attached to it
- SSH to the instance and confirm that you can SSH to it and that you cannot make HTTP requests to Google, Yahoo, etc
  - try executing ```wget http://now.httpbin.org```
- Via the CLI query EC2 for details about the instance, note that it is not currently in the egress-sg security group (```Reservations[*].Instances[*].SecurityGroups```)
  - sample command ```aws ec2 describe-instances --instance-ids i-0fed504c2a3610a5d --region eu-west-1```
- Via the CLI modify the EC2 instance to be in the httpbin-access-sg
  - Obtain the security group ID: ```aws ec2 describe-security-groups --region eu-west-1 --query 'SecurityGroups[*].{Name:GroupName, ID:GroupId}'```
  - Then modify the EC2 instance ```aws ec2 modify-instance-attribute --instance-id i-0fed504c2a3610a5d --groups sg-9e7c88e5 sg-5a748021 --region eu-west-1```
- From the SSH session confirm that you can now make HTTP requests to httpbin.org
**You may need to place the IP for httpbin.org into ```/etc/hosts```**

## implementation of the blog post for automating the update of security groups when AWS publishes IP changes
Part 2:
- In a browser open the IP addresses JSON document published by AWS
- Via the console create an IAM policy that will allow something to modify security groups
- Via the console create a role which that can be assumed by Lambda and has the policy attached
- Via the console create a Lambda function with the role and policy to process the JSON document and update the security groups
- Via the console issue a test event and view the changes reflected in the security group
- From the SSH session confirm that you can query the AWS API but no other websites

## implement a Config Rule that ensures all EC2 instances have the egress-sg security group attached 
Part 3:
- 


# Resources
---
Cloudformation to create users:

