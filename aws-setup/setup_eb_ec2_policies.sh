#!/bin/bash

source common_setup.sh

# Create policy within the beanstalk role for sending emails from the address ADIM_EMAIL
gen_doc iam-ec2-role/policy_send_emails.json
aws iam put-role-policy --role-name aws-elasticbeanstalk-ec2-role --policy-name added-send-emails --policy-document file://${document_file}

# Add policy for bulk messaging
gen_doc iam-ec2-role/policy_bulk_messaging.json
aws iam put-role-policy --role-name aws-elasticbeanstalk-ec2-role --policy-name added-bulk-messaging --policy-document file://${document_file}

# Add policy for box build
gen_doc iam-ec2-role/policy_box_build.json
aws iam put-role-policy --role-name aws-elasticbeanstalk-ec2-role --policy-name added-box-build --policy-document file://${document_file}

aws iam attach-role-policy --role-name aws-elasticbeanstalk-ec2-role --policy-arn arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy
aws iam attach-role-policy --role-name aws-elasticbeanstalk-ec2-role --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
aws iam attach-role-policy --role-name aws-elasticbeanstalk-ec2-role --policy-arn arn:aws:iam::aws:policy/CloudWatchLogsReadOnlyAccess
aws iam attach-role-policy --role-name aws-elasticbeanstalk-ec2-role --policy-arn arn:aws:iam::aws:policy/AmazonSNSFullAccess

cat << EOF
Done
EOF
