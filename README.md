# Technical Assessment

## Sections

- [[I] Terraform and AWS](#terraform-and-aws)
- [[II] Linux, Ansible, and FluentD](#linx-ansible---and-fluentd)
- [[III] Docker](#docker)

---

# Terraform and AWS

Directory structure:

```
tree terraform/
├── data.tf
├── main.tf
├── outputs.tf
├── provider.tf
├── user_data
│   └── nginx.tpl
└── variables.tf
```

## Additional settings

To perform the task a remote backend was used which is described below. However, the result can also be replicated locally. 

To do this you need to specify the values for the following environment variables:

```
export AWS_ACCESS_KEY_ID="string"
export AWS_SECRET_ACCESS_KEY="another-string"
```

And also a Terraform variable __aws_key_pair_public_key__. In it, you need to specify the value of the public key that will be used to access the instance via SSH.
```
export TF_VAR_aws_key_pair_public_key="ssh-rsa AAAAB-long-string-example== o.bandrivsky@inc4.net"
```

## Implementation

If the values of variables in the variables.tf file are empty, the following local parameters will be used.
```
locals {
  instance_name    = "single-assessment"
  root_volume_size = 20
  instance_type    = "t2.micro"

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}
```

To specify the value for _Ubuntu ami_ using the following data source.

```
data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

```

In the default VPC a security group is created with open ports [22, 80, 443].

```
module "assessment_security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "4.9.0"

  name   = "assessment-sg"
  vpc_id = data.aws_vpc.default.id

  egress_rules        = ["all-all"]
  ingress_cidr_blocks = ["0.0.0.0/0"]
  ingress_rules       = ["http-80-tcp", "https-443-tcp", "ssh-tcp"]
}
```

To install Nginx, the user_data mechanism is used with the following content.
```
#!/bin/bash
sudo apt update -y &&
sudo apt install -y nginx
echo "Hello, bloxroute!" > /var/www/html/index.html
```

Additionally, monitoring is enabled, the instance root volume size is set, and tags are specified.

To obtain information about the IP address of the future server, let's display it.
```
output "ec2_public_ip" {
  value = module.ec2_instance.public_ip
}
```

Finally:
```
module "ec2_instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "5.2.1"

  name = var.ec2_name == "" || var.ec2_name == null ? local.instance_name : var.ec2_name

  instance_type = var.ec2_type == "" || var.ec2_type == null ? local.instance_type : var.ec2_type
  ami           = data.aws_ami.ubuntu.id
  key_name      = aws_key_pair.ssh_access.key_name
  monitoring    = true

  vpc_security_group_ids = [
    module.assessment_security_group.security_group_id
  ]

  root_block_device = [
    {
      encrypted   = true
      volume_type = "gp3"
      volume_size = var.ec2_volume_size == null ? local.root_volume_size : var.ec2_volume_size
    },
  ]
  user_data = file("./user_data/nginx.tpl")
  tags      = local.tags
}
```

## Extra credit

To accomplish this task, a remote backend in the form of __Terraform Cloud__ was used.

Some advantages of using Terraform Cloud as a remote backend over a local backend while maintaining state:

    => Centralized State Management
    => State Locking and Consistency
    => Remote Operations and Collaboration
    => Automated Backups and Versioning
    => Integration and Extensibility
    => Scalability and High Availability
    => Access and Permissions Management
    => Greater Stability and Security

While a local backend can be suitable for small-scale projects or individual use, Terraform Cloud offers enhanced collaboration, centralized management, and additional features that streamline the workflow, especially in team environments or larger projects.

So in this case, you need to create/log in to Terraform Cloud and create a new workspace. Then, connect your GitHub repository. Here's an example:

![img-1](https://github.com/OlehBandrivskyi/technical_assessment/blob/5a29dfd3ab34150bb2ae326d6d9f587b89c629b2/img/img1.png)

Also need to fill in the variables section.

![img-2](https://github.com/OlehBandrivskyi/technical_assessment/blob/5a29dfd3ab34150bb2ae326d6d9f587b89c629b2/img/img2.png)

When changes are made to the repository, Terraform plan is triggered.

![img-3](https://github.com/OlehBandrivskyi/technical_assessment/blob/5a29dfd3ab34150bb2ae326d6d9f587b89c629b2/img/img3.png)

And apply the changes:

![img-4](https://github.com/OlehBandrivskyi/technical_assessment/blob/5a29dfd3ab34150bb2ae326d6d9f587b89c629b2/img/img4.png)


We have the IP address, and we can check the availability of nginx, for example, using curl.
```
curl 18.196.176.118
Hello, bloxroute!
```

Now, from localhost, connecting to the server using the previously provided SSH key.

![img-5](https://github.com/OlehBandrivskyi/technical_assessment/blob/5a29dfd3ab34150bb2ae326d6d9f587b89c629b2/img/img5.png)
