# Automated compliance workshop
This workshop was originally created in October of 2017 in support of getting LSEG engaged in governance and using the tools available to them in AWS.

The workshop is intended to be conducted with audience participation in approximately 90 minutes.

The workshop is broken up into 4 parts, the 3rd and 4th of which are optional.

Links to resources from which this content is derived:
- https://aws.amazon.com/blogs/security/how-to-automatically-update-your-security-groups-for-amazon-cloudfront-and-aws-waf-by-using-aws-lambda/
- https://github.com/awslabs/aws-config-rules
- https://aws.amazon.com/blogs/compute/automating-security-group-updates-with-aws-lambda/

## Part 1: demonstrate the security groups concept
Simple demonstration of security groups and the CLI ability to view and modify AWS resources

### Steps:
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

## Part 2: Demonstrate a Lambda to modify security group egress rules
Implementation of a modification of the blog post for automating the update of security groups when AWS publishes IP changes

**Note:**
The Lambda in this part will update security groups based on their region and service.  Create security groups with three tags to control regional and global access to services: 
- managed = true
- region = <one of global, eu-west-1, eu-west-2, etc>
- service = <one of ec2, amazon, cloudfront, etc>

### Steps
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

## Part 3: Demonstrate Config rules

Implement a Config Rule that ensures all EC2 instances have mandatory security groups attached 

**Note:** Part 3 and 4 contain Lambda functions that seek out EC2 instances which do not have mandatory security groups attached.  In preparation for these parts create one or more security groups that have a tag of 'mandatory' = 'true'.  The Lambda functiosn will ensure that all EC2 instances that do not have a tag of 'exempt' = 'true' have the mandatory security groups attached.**

### Steps:
- Via the console create an IAM policy that will allow a Lambda function to modify EC2 instances
- Via the console create a role that can be assumed by Lambda and has the policy attached
- Via the console create a Lambda function with the role and policy to process a Config event and update EC2 instances
- Via the console create a Config rule which points at the ARN of the Lambda function, configure it to trigger on security group changes or EC2 instance changes
- Create an EC2 instance that is non-compliant

**Note:** Config can take up to 10 minutes to notice the creation of the EC2 instance and apply its configuration rules.  If undesired consider using CloudWatch Events for near real-time operation.

## Step 4: CloudWatch Rules is faster than Config

For faster reaction times implement a CloudWatch Rule

### Steps:
- Via the console create an IAM policy that will allow a Lambda function to modify EC2 instances
- Via the console create a role that can be assumed by Lambda and has the policy attached
- Via the console create a Lambda function with the role and policy to process a CloudWatch event and update EC2 instances
- Via the console create a CloudWatch Rule that triggers when an EC2 instance changes state to either Pending or Running, configure the rule to execute the Lambda function
- Via the console create an EC2 instance that is not a part of the mandatory security group, within seconds the newly created EC2 instance should be updated to have the mandatory security groups

