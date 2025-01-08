variable "aws_region" {
  default = "us-east-1"
}

variable "ami_id" {
  description = "AMI ID for EC2 instance"
  default     = "ami-01816d07b1128cd2d"
}

variable "instance_type" {
  description = "Instance type for EC2"
  default     = "t2.micro"
}

variable "key_name" {
  description = "SSH key name for EC2 instance"
  default     = "my-key-pair"
}

variable "cluster_name" {
  description = "Name of the EKS cluster"
  default     = "private-eks-cluster"
}
