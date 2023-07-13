variable "aws_key_pair_public_key" {
  type      = string
  sensitive = true
}

variable "ec2_name" {
  type = string
}

variable "ec2_type" {
  type = string
}

variable "ec2_volume_size" {
  type    = number
  default = 20
}
