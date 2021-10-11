#!/bin/bash

source common_setup.sh

# Create group: box-admins
aws iam create-group --group-name box-admins

# Create policy within the beanstalk role for reading IAM users in group box-admins
gen_doc iam-ec2-role/policy_box_admins.json
aws iam put-role-policy --role-name aws-elasticbeanstalk-ec2-role --policy-name added-box-admins --policy-document file://${document_file}

cat << EOF
In https://console.aws.amazon.com/systems-manager/session-manager/preferences?region=us-east-1
Edit and check "Enable Run As support for Linux instances" leaving the "Operating system user name" blank

Add sysadmin users to the IAM group "box-admins"
To each of these users add a tag:
  SSMSessionRunAs = <IAM username>
EOF
