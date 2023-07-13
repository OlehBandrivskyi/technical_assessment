locals {
  instance_name    = "single-assessment"
  root_volume_size = 20
  instance_type    = "t2.micro"

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

resource "aws_key_pair" "ssh_access" {
  public_key = var.aws_key_pair_public_key
}

module "assessment_security_group" {
  source  = "terraform-aws-modules/security-group/aws"
  version = "4.9.0"

  name   = "assessment-sg"
  vpc_id = data.aws_vpc.default.id

  egress_rules        = ["all-all"]
  ingress_cidr_blocks = ["0.0.0.0/0"]
  ingress_rules       = ["http-80-tcp", "https-443-tcp", "ssh-tcp"]
}

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
