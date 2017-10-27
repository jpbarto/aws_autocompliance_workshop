This workshop was originally created in October of 2017 in support of getting LSEG engaged in governance and using the tools available to them in AWS.

The workshop is intended to be conducted with audience participation in approximately 90 minutes.

The workshop is broken up into 3 parts, the 3rd of which is optional.

Links to resources from which this content is derived:
- https://aws.amazon.com/blogs/security/how-to-automatically-update-your-security-groups-for-amazon-cloudfront-and-aws-waf-by-using-aws-lambda/
- https://github.com/awslabs/aws-config-rules

## simple demonstration of security groups and the CLI ability to view and modify AWS resources
Part 1:
- Via the console create a security group that permits SSH ingress with no egress (ssh-sg) 
  
  - EC2 > Security Groups > Create Security Group
  - Remove egress permissions, permit SSH ingress
- Via the console create a security group that will control access to external websites, do not add any rules as yet (www-sg)
  
  - EC2 > Security Groups > Create Security Group
- Via the console create an EC2 instance with only the ssh-sg group attached to it
- Via a web browser navigate to https://httpjs.net and record the url it creates for you, resolve the IP of the url using nslookup
- SSH to the instance and confirm that you can SSH to it and that you cannot make HTTP requests to Google, Yahoo, or the httpjs URL
  - try executing ```curl https://<url>.httpjs.net```
- Via the CLI query EC2 for details about the instance, note that it is not currently in the www-sg security group (```Reservations[*].Instances[*].SecurityGroups```)
  - sample command ```aws ec2 describe-instances --instance-ids <instance-id> --region eu-west-1```
- Via the CLI modify the EC2 instance to be in the www-sg
  - Obtain the security group ID: ```aws ec2 describe-security-groups --region eu-west-1 --query 'SecurityGroups[*].{Name:GroupName, ID:GroupId}'```
  - Then modify the EC2 instance ```aws ec2 modify-instance-attribute --instance-id <instance-id> --groups <group-1> <group-2> --region eu-west-1```
- Try again to reach the HTTPJS site using ```curl https://<url>.httpjs.net```
- Via the console add the IP address resolved earlier for HTTPJS to the www-sg group's egress rules and try to execute curl again, it should now work
- From the SSH session confirm that you can now make HTTP requests to httpjs.net
- Confirm that you cannot execute ```aws ec2 describe-instances```

## implementation of the blog post for automating the update of security groups when AWS publishes IP changes
Part 2:
- In a browser open the IP addresses JSON document published by AWS
  - https://ip-ranges.amazonaws.com/ip-ranges.json
  - sample ```jq``` commands:
    - list all IP prefixes that are globally available for the AMAZON service:
      jq '.prefixes[] | select (.region == "GLOBAL" and .service == "AMAZON") | .ip_prefix' ip-ranges.json
    - list all unique regions
      jq '.prefixes[].region' ip-ranges.json | sort -u
    - list all unique services
      jq '.prefixes[].service' ip-ranges.json | sort -u

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
Create security groups with three tags to control regional and global access to services: 
- managed = true
- region = <one of global, eu-west-1, eu-west-2, etc>
- service = <one of ec2, amazon, cloudfront, etc>
