# Setting up an application

Run through the follow steps in AWS (console or CLI), entering the IDs generated in [environment-name]-env.vars

- Change directory to `deploy/aws/restructure-demo`
- Copy **dev-secrets.sample** to **dev-secrets**

- Edit **dev-secrets**

  - generate `rails secret` for each of the long random keys
  - generate a random password to be used by the Rails DB user to access the database
  - `gpg -c dev-secrets` and use a GPG password to encrypt
  - `rm dev-secrets`

- Optionally create a VPC, or use the default

  - If using default VPC, enter ID in **VPC_ID**
    - Enter _zone a_ and _zone b_ subnet ID(s) in **VPC_SUBNETS** (comma separated, no spaces)
  - If created a VPC, enter ID in **VPC_ID**

    - Create an Internet Gateway
      - Attach it to VPC
    - Create subnets for:
      - web (availability zone a)
      - data (availability zone a)
      - data failover (availability zone b)
    - Enter subnet ID(s) in **VPC_SUBNETS** (comma separated, no spaces)

- Create a PostgreSQL RDS database

  - Instance identifier: `restructure-demo-db`
  - Select the new VPC and primary availability group
  - Enable public access
  - Create a password for the master postgres user
  - Create a new security group for it in _zone a_: `DEV-demo-rds-server`
  - Enter new security group ID in **DB_SECURITY_GROUP**
  - Enter endpoint name in **DB_HOST**
  - Enter the database name **restr** in **DB_NAME**


- Create a security group for web access to the app server: `DEV-demo-app-server`

  - Add HTTP and HTTPS access
  - Enter the ID in **APPSVR_SECURITY_GROUP**

- Edit security group **DEV-demo-rds-server**
  - change source to security group *DEV-demo-app-server*


- Create s3 bucket named **restructure-demo-assets** with default settings
  - Edit IAM role 
  - add inline policy named **RestructureAssets**:

      {
          "Version": "2012-10-17",
          "Statement": [
              {
                  "Sid": "ServiceAssetRead0",
                  "Effect": "Allow",
                  "Action": [
                      "s3:ListBucket"
                  ],
                  "Resource": [
                      "arn:aws:s3:::restructure-demo-assets"
                  ]
              },
              {
                  "Sid": "ServiceAssetRead1",
                  "Effect": "Allow",
                  "Action": [
                      "s3:GetObject"
                  ],
                  "Resource": [
                      "arn:aws:s3:::restructure-demo-assets/*"
                  ]
              }
          ]
      }


- Edit the file `aws/restructure-demo/ebextensions/dev/0-init-ec2-instance.config`

  - replace the value for `option_name: SecurityGroups` with the values of:
    **APPSVR_SECURITY_GROUP**,**DB_SECURITY_GROUP**

- Create a security group for EFS, named **DEV-demo-efs**
  - Set an inbound rule for *NFS* from source security group *DEV-demo-app-server*

- Create an EFS service for file storage, called **app-dev-efs1**
  - In **deploy/aws/restructure-demo/ebextensions/dev/setup-filestore.config** set the environment variable
    around line 11 as: `FSID=<the new filesystem ID>`
  - Add the new security group **DEV-demo-efs** to _zone a_


- In Route 53, create a hosted zone for your app server (for example restructure.<your-domain.tld>)
  - If this is a subdomain of another domain, use the nameservers provided to set the nameservers 
    for this subdomain in your primary domain's hosted zone.

- In IAM, select Role **aws-elasticbeanstalk-ec2-role**
  - Add inline policy as JSON 
  - Paste in the following, replacing YOURHOSTEDZONEID with the ID of your hosted zone in Route 53

    {
        "Version": "2012-10-17",
        "Id": "certbot-dns-route53 sample policy",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "route53:ListHostedZones",
                    "route53:GetChange"
                ],
                "Resource": [
                    "*"
                ]
            },
            {
                "Effect" : "Allow",
                "Action" : [
                    "route53:ChangeResourceRecordSets"
                ],
                "Resource" : [
                    "arn:aws:route53:::hostedzone/YOURHOSTEDZONEID"
                ]
            }
        ]
    }


- In the EC2 console, create a key pair:

  - Name: `restructure-aws-eb`
  - Move the downloaded file to `~/.ssh`
  - Change the file permissions to 600 (read/write by owner only)

- View the web page and find a supported version of Ruby 2.6 running Passenger:
  https://docs.aws.amazon.com/elasticbeanstalk/latest/platforms/platforms-supported.html#platforms-supported.ruby

  - Update **EB_PLATFORM** as appropriate

- Assuming RDS database has been initialized, now create a demo database in Postgres:

  - `cd ../ReStructure; app-scripts/create-aws-db.sh; cd -`
  - when prompted, enter the postgres DB user password

- On the command line, change directory to `restructure-build`

  - Run `deploy/aws-eb-deploy.sh`

- For each question, respond appropriately

  - Enter 1 to clone from git: enter a tag name or **new-master** to use the latest deployable version
  - Select EB name to deploy: `restructure-demo`
  - Enter environment name to deploy: `dev`
  - Enter the GPG key used to encrypt **dev-secrets**
  - Provide the access key and secret for an IAM user with sufficient rights to deploy
  - Enter default region name: `us-east-1`
  - Default output format: `json`
  - Setup the environment or use an existing one?: `setup`
  - Confirm DB
  - Ensure the database has been created and seeded: hit enter

- In Route 53 Point the A record for the domain name to the new server (referencing the EB application)

- ssh to the server and setup the admin user and app according the README
