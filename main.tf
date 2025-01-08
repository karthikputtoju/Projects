# Specify the AWS provider
provider "aws" {
  region = "us-east-1" 
}

# VPC 1: Provider VPC
resource "aws_vpc" "vpc1" {
  cidr_block = "10.0.0.0/16"
  tags = {
    Name = "provider-vpc"
  }
}

# Create a public subnet in VPC 1 with a route table and internet gateway for public access
resource "aws_subnet" "vpc1_public" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = "10.0.3.0/24"
  availability_zone = "us-east-1a"
  tags = {
    Name = "provider-public-subnet"
  }
}

resource "aws_internet_gateway" "vpc1_igw" {
  vpc_id = aws_vpc.vpc1.id
  tags = {
    Name = "provider-igw"
  }
}

resource "aws_route_table" "vpc1_public_rt" {
  vpc_id = aws_vpc.vpc1.id
}

resource "aws_route_table_association" "vpc1_public_association" {
  subnet_id      = aws_subnet.vpc1_public.id
  route_table_id = aws_route_table.vpc1_public_rt.id
}

resource "aws_route" "vpc1_public_rt" {
  route_table_id         = aws_route_table.vpc1_public_rt.id
  destination_cidr_block = "10.0.3.0/24"
  gateway_id             = aws_internet_gateway.vpc1_igw.id
}

# create a two  private subnet in VPC 1 with a route table  with nat gateway for private access  
resource "aws_subnet" "vpc1_private_1" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "us-east-1a"
  tags = {
    Name = "provider-private-subnet1"
  }
}

resource "aws_subnet" "vpc1_private_2" {
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = "10.0.2.0/24"
  availability_zone = "us-east-1b"
    tags = {
        Name = "provider-private-subnet2"
    }
}

resource "aws_route_table" "vpc1_private_rt" {
  vpc_id = aws_vpc.vpc1.id
}

resource "aws_route_table_association" "vpc1_private_association" {
  subnet_id      = aws_subnet.vpc1_private_1.id
  route_table_id = aws_route_table.vpc1_private_rt.id
}

resource "aws_route_table_association" "vpc1_private_association2" {
  subnet_id      = aws_subnet.vpc1_private_2.id
  route_table_id = aws_route_table.vpc1_private_rt.id
}

# create a NAT gateway in VPC 1 for private subnet access
resource "aws_nat_gateway" "vpc1_nat" {
  allocation_id = aws_eip.vpc1_nat.id
  subnet_id     = aws_subnet.vpc1_public.id
}

resource "aws_eip" "vpc1_nat" {
  associate_with_private_ip = true
}

resource "aws_route" "vpc1_private_rt" {
  route_table_id         = aws_route_table.vpc1_private_rt.id
  destination_cidr_block = "10.0.1.0/24"
  nat_gateway_id         = aws_nat_gateway.vpc1_nat.id
}

resource "aws_route" "vpc1_private_rt2" {
  route_table_id         = aws_route_table.vpc1_private_rt.id
  destination_cidr_block = "10.0.2.0/24"
  nat_gateway_id         = aws_nat_gateway.vpc1_nat.id
}

# VPC 2: Consumer VPC
resource "aws_vpc" "vpc2" {
  cidr_block = "10.1.0.0/16"
  tags = {
    Name = "consumer-vpc"
  }
}

# Create a public and private subnet in VPC 2 with a route table and NAT gateway for private access
resource "aws_subnet" "vpc2_public" {
  vpc_id            = aws_vpc.vpc2.id
  cidr_block        = "10.1.3.0/24"
  availability_zone = "us-east-1a"
  tags = {
    Name = "consumer-public-subnet"
  }
}

resource "aws_subnet" "vpc2_private" {
  vpc_id            = aws_vpc.vpc2.id
  cidr_block        = "10.1.1.0/24"
  availability_zone = "us-east-1a"
    tags = {
        Name = "consumer-private-subnet"
    }
}

resource "aws_route_table" "vpc2_public_rt" {
  vpc_id = aws_vpc.vpc2.id
}

resource "aws_route_table_association" "vpc2_public_association" {
  subnet_id      = aws_subnet.vpc2_public.id
  route_table_id = aws_route_table.vpc2_public_rt.id
}

resource "aws_route_table" "vpc2_private_rt" {
  vpc_id = aws_vpc.vpc2.id
}

resource "aws_route_table_association" "vpc2_private_association" {
  subnet_id      = aws_subnet.vpc2_private.id
  route_table_id = aws_route_table.vpc2_private_rt.id
}

resource "aws_internet_gateway" "vpc2_igw" {
  vpc_id = aws_vpc.vpc2.id
  tags = {
    Name = "consumer-igw"
  }
}

resource "aws_nat_gateway" "vpc2_nat" {
  allocation_id = aws_eip.vpc2_nat.id
  subnet_id     = aws_subnet.vpc2_public.id
}

resource "aws_eip" "vpc2_nat" {
  associate_with_private_ip = true
}

resource "aws_route" "vpc2_public_rt" {
  route_table_id         = aws_route_table.vpc2_public_rt.id
  destination_cidr_block = "10.1.3.0/24"
  gateway_id             = aws_internet_gateway.vpc2_igw.id
}

resource "aws_route" "vpc2_private_rt" {
  route_table_id         = aws_route_table.vpc2_private_rt.id
  destination_cidr_block = "10.1.1.0/24"
  nat_gateway_id         = aws_nat_gateway.vpc2_nat.id
}

# EC2 Instance in VPC 2 (Consumer VPC) Bastion Host
resource "aws_instance" "bastion_ec2" {
  ami           = "ami-01816d07b1128cd2d" 
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.vpc2_public.id
  key_name      = "my-key-pair" 
  tags = {
    Name = "bastion-ec2-instance"
  }
}

# Security group into the bastion host and 22 port
resource "aws_security_group" "bastion_sg" {
  name        = "bastion-host-sg"
  description = "Allow inbound traffic from anywhere"
  vpc_id      = aws_vpc.vpc2.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "bastion-host-sg"
  }
}

# Security group for the EKS Cluster (VPC 1)
resource "aws_security_group" "eks_cluster_sg" {
  name        = "eks-cluster-sg"
  description = "Allow inbound traffic from VPC 2"
  vpc_id      = aws_vpc.vpc1.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [aws_vpc.vpc2.cidr_block]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = {
    Name = "eks-cluster-sg"
  }
}

# Security group for the EKS Node Group (VPC 1)
resource "aws_security_group" "eks_node_group_sg" {
  name        = "eks-node-group-sg"
  description = "Allow inbound traffic from the EKS Cluster"
  vpc_id      = aws_vpc.vpc1.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    security_groups = [aws_security_group.eks_cluster_sg.id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    }
    tags = {
    Name = "eks-node-group-sg"
  }
}

# Security group for the EKS Cluster (VPC 1)
resource "aws_security_group" "eks_sg" {
  name        = "eks-cluster-sg"
  description = "Allow inbound traffic to the EKS Cluster API server"
  vpc_id      = aws_vpc.vpc1.id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    }
    ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    }
    ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    }
    ingress {
    from_port   = 6443
    to_port     = 6443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    }
    ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    security_groups = [aws_security_group.eks_cluster_sg.id]
    }
    egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    }
    tags = {
    Name = "eks-cluster-sg"
  }
}

# Security group for the EC2 instance (VPC 2)
resource "aws_security_group" "ec2_sg" {
  name        = "consumer-ec2-sg"
  description = "Allow inbound traffic for SSH (port 22) and kubectl (port 443)"
  vpc_id      = aws_vpc.vpc2.id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Allow SSH from anywhere (or restrict to specific IPs)
    }
    ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Allow SSH from anywhere (or restrict to specific IPs)
    }
    egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    }
    tags = {
    Name = "consumer-ec2-sg"
    }
}

# IAM Role for EKS Cluster on VPC 1
resource "aws_iam_role" "eks_role" {
  name = "eks-cluster-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Principal = {
          Service = "eks.amazonaws.com"
        }
        Effect    = "Allow"
        Sid       = ""
      },
    ]
    })
}

# Attach policies to the EKS Role
resource "aws_iam_role_policy_attachment" "eks_role_policy" {
  role       = aws_iam_role.eks_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role_policy_attachment" "eks_service_policy" {
  role       = aws_iam_role.eks_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSServicePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_vpc_policy" {
  role       = aws_iam_role.eks_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonVPCFullAccess"
}

# EKS Cluster in VPC 1
resource "aws_eks_cluster" "eks_cluster" {
  name     = "private-eks-cluster"
  role_arn = aws_iam_role.eks_role.arn
  vpc_config {
    subnet_ids = [aws_subnet.vpc1_private_1.id, aws_subnet.vpc1_private_2.id]
    endpoint_private_access = true
    endpoint_public_access = false
  }
}

# Output the EKS Cluster name
output "eks_cluster_name" {
  value = aws_eks_cluster.eks_cluster.name
}

/*
# Kubernetes Provider Configuration
provider "kubernetes" {
  host                   = data.aws_eks_cluster.eks.endpoint
  cluster_ca_certificate = base64decode(data.aws_eks_cluster.eks.certificate_authority[0].data)
  token                  = data.aws_eks_cluster_auth.eks.token
}

# AWS Auth ConfigMap for Node Group
resource "kubernetes_config_map" "aws_auth" {
  metadata {
    name      = "aws-auth"
    namespace = "kube-system"
  }

  data = {
    mapRoles = jsonencode([{
      rolearn  = aws_iam_role.eks_node_group_role.arn
      username = "system:node:{{EC2PrivateDNSName}}"
      groups   = ["system:bootstrappers", "system:nodes"]
    }]) 
    mapUsers = jsonencode([{
      userarn  = "arn:aws:iam::262615930633:user/karthikputtoju"
      username = "karthikputtoju"
      groups   = ["system:masters"]
    }])
  }
}

# Data source to get the EKS Cluster endpoint
data "aws_eks_cluster" "eks" {
  name = aws_eks_cluster.eks_cluster.name
}

# Data source to get the EKS Cluster authentication token
data "aws_eks_cluster_auth" "eks" {
  name = aws_eks_cluster.eks_cluster.name
}*/

# EKS Cluster endpoint access to private
resource "aws_route" "eks_cluster" {
  route_table_id            = aws_route_table.vpc1_private_rt.id
  destination_cidr_block    = "10.0.0.0/16"
  nat_gateway_id            = aws_nat_gateway.vpc1_nat.id
}

# CoreDNS Configuration Nat Gateway and Route Table for EKS Cluster
resource "aws_route" "coredns" {
  route_table_id            = aws_route_table.vpc1_private_rt.id
  destination_cidr_block    = "0.0.0.0/0"
  nat_gateway_id            = aws_nat_gateway.vpc1_nat.id
}

# EKS Cluster Add-ons
resource "aws_eks_addon" "kube_proxy" {
  cluster_name = aws_eks_cluster.eks_cluster.name
  addon_name   = "kube-proxy"
}

resource "aws_eks_addon" "core_dns" {
  cluster_name = aws_eks_cluster.eks_cluster.name
  addon_name   = "coredns"
}

resource "aws_eks_addon" "vpc_cni" {
  cluster_name = aws_eks_cluster.eks_cluster.name
  addon_name   = "vpc-cni"
}

# IAM Role for EKS Managed Node Group
resource "aws_iam_role" "eks_node_group_role" {
  name = "eks-node-group-role"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Effect    = "Allow"
        Sid       = ""
      },
      {
        Action    = "sts:AssumeRole"
        Principal = {
          Service = "eks.amazonaws.com"
        }
        Effect    = "Allow"
        Sid       = ""
      },
    ]
    })
}

# Attach policies to the EKS Node Group Role
resource "aws_iam_role_policy_attachment" "eks_node_group_policy" {
  role       = aws_iam_role.eks_node_group_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_cni_policy" {
  role       = aws_iam_role.eks_node_group_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "eks_container_registry_ro_policy" {
  role       = aws_iam_role.eks_node_group_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# IAM Instance Profile for EKS Managed Node Group
resource "aws_iam_instance_profile" "eks_node_group_profile" {
  name = "eks-node-group-profile"
  role = aws_iam_role.eks_node_group_role.name
}

# EKS Managed Node Group
resource "aws_eks_node_group" "eks_node_group" {
  cluster_name    = aws_eks_cluster.eks_cluster.name
  node_group_name = "eks-node-group"
  node_role_arn   = aws_iam_role.eks_node_group_role.arn
  subnet_ids      = [aws_subnet.vpc1_private_1.id, aws_subnet.vpc1_private_2.id]

  scaling_config {
    desired_size = 2
    max_size     = 2
    min_size     = 2
  }

  ami_type  = "AL2_x86_64"
  instance_types = ["t3.medium"]
  capacity_type = "ON_DEMAND"
  disk_size = 20
  force_update_version = false
  remote_access {
    ec2_ssh_key = "my-key-pair"
    source_security_group_ids = [aws_security_group.eks_node_group_sg.id, aws_security_group.eks_cluster_sg.id] 
  }
  
  tags = {
    Name = "EKS Node Group"
  }
}

# IAM Role for EC2 Instance
resource "aws_iam_role" "ec2_role" {
  name = "ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "sts:AssumeRole"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
        Effect    = "Allow"
        Sid       = ""
      },
    ]
  })
}

# Attach policies to EC2 Role
resource "aws_iam_role_policy_attachment" "ec2_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "ec2_vpc_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonVPCFullAccess"
}

# IAM Instance Profile for EC2 Instance
resource "aws_iam_instance_profile" "ec2_instance_profile" {
  name = "ec2-instance-profile"
  role = aws_iam_role.ec2_role.name
}

# Check the EKS Cluster Worker Node status
resource "null_resource" "eks_worker_status" {
  provisioner "local-exec" {
    command = "aws eks wait node-group-active --cluster-name private-eks-cluster --nodegroup-name eks-node-group"
  }
}

# VPC Endpoint Service in VPC 1
resource "aws_vpc_endpoint_service" "eks_service" {
  acceptance_required = false
  allowed_principals  = ["arn:aws:iam::262615930633:user/karthikputtoju"]
}

# Check the EKS Cluster access point status
resource "null_resource" "eks_access_point_status" {
  provisioner "local-exec" {
    command = "aws eks wait access-point-active --cluster-name private-eks-cluster --access-point-id <access-point-id>"
  }
}

# Load Balancer and Target Group with healthy for the VPC Endpoint Service
resource "aws_lb" "vpc1_endpoint_service_lb" {
  name               = "vpc1-endpoint-service-lb"
  internal           = true
  load_balancer_type = "network"
  subnets            = [aws_subnet.vpc1_private_1.id, aws_subnet.vpc1_private_2.id]
  tags = {
    Name = "vpc1-endpoint-service-lb"
  }
}

resource "aws_lb_target_group" "vpc1_endpoint_service_tg" {
  name        = "vpc1-endpoint-service-tg"
  port        = 443
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = aws_vpc.vpc1.id
  health_check {
    enabled = true
    protocol = "TCP"
  }
  tags = {
    Name = "vpc1-endpoint-service-tg"
  }
}

# Load Balancer Listener for the VPC Endpoint Service 
resource "aws_lb_listener" "vpc1_endpoint_service_listener" {
  load_balancer_arn = aws_lb.vpc1_endpoint_service_lb.arn
  port              = 443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.vpc1_endpoint_service_tg.arn
  }
}

# VPC Endpoint Service Listener Rule for the VPC Endpoint Service
resource "aws_lb_listener_rule" "vpc1_endpoint_service_listener_rule" {
  listener_arn = aws_lb_listener.vpc1_endpoint_service_listener.arn
  priority     = 100

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.vpc1_endpoint_service_tg.arn
  }

  condition {
    host_header {
      values = [aws_vpc_endpoint_service.eks_service.private_dns_name]
    }
  }
}

# VPC Endpoint Service Connection Notification in VPC 1
resource "aws_vpc_endpoint_connection_notification" "eks_service_connection_notification" {
  connection_notification_arn = "arn:aws:sns:us-east-1:123456789012:MySNSTopic"
  vpc_endpoint_id             = aws_vpc_endpoint_service.eks_service.id
  connection_events           = ["Accept", "Reject", "Terminate"]
}

# VPC Endpoint in VPC 2
resource "aws_vpc_endpoint" "consumer_vpc_endpoint" {
  vpc_endpoint_type   = aws_vpc_endpoint_service.eks_service.service_type
  service_name        = aws_vpc_endpoint_service.eks_service.service_name
  route_table_ids     = [aws_route_table.vpc2_private_rt.id]
  subnet_ids          = [aws_subnet.vpc2_private.id]
  vpc_id              = aws_vpc.vpc2.id
  security_group_ids  = [aws_security_group.ec2_sg.id]
  private_dns_enabled = true
  tags = {
    Name = "consumer-vpc-endpoint"
  }
}

# VPC Endpoint Route in VPC 2
resource "aws_route" "consumer_vpc_endpoint_route" {
  route_table_id         = aws_route_table.vpc2_private_rt.id
  destination_cidr_block = aws_vpc_endpoint_service.eks_service.private_dns_name
  vpc_endpoint_id        = aws_vpc_endpoint.consumer_vpc_endpoint.id
}

# EC2 Instance in VPC 2 (Consumer VPC)
resource "aws_instance" "consumer_ec2_instance" {
  ami           = "ami-01816d07b1128cd2d" 
  instance_type = "t2.micro"
  key_name = "my-key-pair"
  subnet_id     = aws_subnet.vpc2_private.id
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  iam_instance_profile = aws_iam_instance_profile.ec2_instance_profile.name
  user_data = <<-EOF
              #!/bin/bash
              # Update the system
              yum update -y
              # Install required packages
              yum install -y jq tar gzip curl unzip wget --skip-broken
              # Install AWS CLI v2
              curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
              unzip awscliv2.zip
              sudo ./aws/install --update
              rm -rf awscliv2.zip aws/
              aws --version
              # Install kubelet
              sudo yum install -y kubelet
              # Install kubectl
              curl -LO https://dl.k8s.io/release/v1.26.3/bin/linux/amd64/kubectl
              chmod +x ./kubectl
              sudo mv ./kubectl /usr/local/bin/kubectl
              kubectl version --client
              EOF
  tags = {
    Name = "consumer-ec2-instance"
  }
}

# Kubectl get nodes on EC2 private instance on VPC 2   
resource "null_resource" "kubectl_get_nodes" {
  provisioner "local-exec" {
    command = "kubectl get nodes"
  }
}
