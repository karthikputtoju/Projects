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

resource "aws_subnet" "vpc1_public" {
  count             = 2
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = element(["10.0.1.0/24", "10.0.2.0/24"], count.index)
  map_public_ip_on_launch = true
  tags = {
    Name = "provider-public-subnet-${count.index + 1}"
  }
}

resource "aws_subnet" "vpc1_private" {
  count             = 2
  vpc_id            = aws_vpc.vpc1.id
  cidr_block        = element(["10.0.3.0/24", "10.0.4.0/24"], count.index)
  tags = {
    Name = "provider-private-subnet-${count.index + 1}"
  }
}

resource "aws_internet_gateway" "vpc1_igw" {
  vpc_id = aws_vpc.vpc1.id
  tags = {
    Name = "provider-igw"
  }
}

resource "aws_nat_gateway" "vpc1_nat" {
  allocation_id = aws_eip.vpc1_nat.id
  subnet_id     = aws_subnet.vpc1_public[0].id
  tags = {
    Name = "provider-nat-gateway"
  }
}

resource "aws_eip" "vpc1_nat" {
  associate_with_private_ip = true
}

resource "aws_route_table" "vpc1_public_rt" {
  vpc_id = aws_vpc.vpc1.id
}

resource "aws_route_table_association" "vpc1_public_association" {
  count          = 2
  subnet_id      = aws_subnet.vpc1_public[count.index].id
  route_table_id = aws_route_table.vpc1_public_rt.id
}

resource "aws_route_table" "vpc1_private_rt" {
  vpc_id = aws_vpc.vpc1.id
}

resource "aws_route_table_association" "vpc1_private_association" {
  count          = 2
  subnet_id      = aws_subnet.vpc1_private[count.index].id
  route_table_id = aws_route_table.vpc1_private_rt.id
}

# VPC 2: Consumer VPC
resource "aws_vpc" "vpc2" {
  cidr_block = "10.1.0.0/16"
  tags = {
    Name = "consumer-vpc"
  }
}

resource "aws_subnet" "vpc2_public" {
  count             = 1
  vpc_id            = aws_vpc.vpc2.id
  cidr_block        = "10.1.1.0/24"
  map_public_ip_on_launch = true
  tags = {
    Name = "consumer-public-subnet-${count.index + 1}"
  }
}

resource "aws_subnet" "vpc2_private" {
  count             = 1
  vpc_id            = aws_vpc.vpc2.id
  cidr_block        = "10.1.2.0/24"
  tags = {
    Name = "consumer-private-subnet-${count.index + 1}"
  }
}

resource "aws_internet_gateway" "vpc2_igw" {
  vpc_id = aws_vpc.vpc2.id
  tags = {
    Name = "consumer-igw"
  }
}

resource "aws_nat_gateway" "vpc2_nat" {
  allocation_id = aws_eip.vpc2_nat.id
  subnet_id     = aws_subnet.vpc2_public[0].id
  tags = {
    Name = "consumer-nat-gateway"
  }
}

resource "aws_eip" "vpc2_nat" {
  associate_with_private_ip = true
}

resource "aws_route_table" "vpc2_public_rt" {
  vpc_id = aws_vpc.vpc2.id
}

resource "aws_route_table_association" "vpc2_public_association" {
  count          = 1
  subnet_id      = aws_subnet.vpc2_public[count.index].id
  route_table_id = aws_route_table.vpc2_public_rt.id
}

resource "aws_route_table" "vpc2_private_rt" {
  vpc_id = aws_vpc.vpc2.id
}

resource "aws_route_table_association" "vpc2_private_association" {
  count          = 1
  subnet_id      = aws_subnet.vpc2_private[count.index].id
  route_table_id = aws_route_table.vpc2_private_rt.id
}

# EC2 Instance in VPC 2 (Consumer VPC) Bastion Host
resource "aws_instance" "bastion_ec2" {
  ami           = "ami-01816d07b1128cd2d" 
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.vpc2_public[0].id
  key_name      = "my-key-pair" 
  tags = {
    Name = "bastion-ec2-instance"
  }
}

# configure bastion host to access the private instances
resource "aws_security_group" "bastion_sg" {
  name        = "bastion-host-sg"
  description = "Allow inbound traffic from anywhere"
  vpc_id      = aws_vpc.vpc2.id

  ingress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Provider CoreDNS Status with VPC 1 NatGateway and Route Table
resource "aws_route" "coredns" {
  route_table_id            = aws_route_table.vpc1_private_rt.id
  destination_cidr_block    = "10.1.0.0/16"
  nat_gateway_id            = aws_nat_gateway.vpc1_nat.id
}

# IAM Role for EKS Cluster
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
    subnet_ids = aws_subnet.vpc1_private[*].id
  }
}

# Data source to get the EKS Cluster endpoint
data "aws_eks_cluster" "eks" {
  name = aws_eks_cluster.eks_cluster.name
}

# Data source to get the EKS Cluster certificate
data "aws_eks_cluster_auth" "eks" {
  name = aws_eks_cluster.eks_cluster.name
}

# Kubernetes provider configuration
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

# EKS Cluster Add-ons
resource "aws_eks_addon" "vpc_cni" {
  cluster_name = var.cluster_name
  addon_name   = "vpc-cni"
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name = var.cluster_name
  addon_name   = "kube-proxy"
}

resource "aws_eks_addon" "core_dns" {
  cluster_name = var.cluster_name
  addon_name   = "coredns"
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

# EKS Managed Node Group
resource "aws_eks_node_group" "eks_node_group" {
  cluster_name    = var.cluster_name
  node_group_name = "eks-node-group"
  node_role_arn   = aws_iam_role.eks_node_group_role.arn
  subnet_ids      = aws_subnet.vpc1_private[*].id

  scaling_config {
    desired_size = 2
    max_size     = 2
    min_size     = 1
  }

  ami_type  = "AL2_x86_64"
  instance_types = ["t3.medium"]

  tags = {
    Name = "EKS Node Group"
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
    cidr_blocks = ["10.1.0.0/16"] # Allow access from Consumer VPC (VPC 2)
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
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
  role = aws_iam_role.vpc_ec2_role.name
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
    cidr_blocks = ["10.0.0.0/16"] # Allow kubectl access from VPC 1
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# VPC Endpoint load balancer and target group for the VPC Endpoint Service
resource "aws_lb" "vpc1_endpoint_service_lb" {
  name               = "vpc1-endpoint-service-lb"
  internal           = true
  load_balancer_type = "network"
  subnets            = aws_subnet.vpc1_private[*].id
}

resource "aws_lb_target_group" "vpc1_endpoint_service_tg" {
  name        = "vpc1-endpoint-service-tg"
  port        = 443
  protocol    = "TCP"
  target_type = "ip"
  vpc_id      = aws_vpc.vpc1.id
}

resource "aws_lb_listener" "vpc1_endpoint_service_listener" {
  load_balancer_arn = aws_lb.vpc1_endpoint_service_lb.arn
  port              = 443
  protocol          = "TCP"

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.vpc1_endpoint_service_tg.arn
  }
}

# Create a VPC Endpoint Service in VPC 1 for the EKS API server
resource "aws_vpc_endpoint_service" "eks_service" {
  acceptance_required = true
}

# Create a VPC Endpoint in VPC 2 to connect to the VPC Endpoint Service in VPC 1
resource "aws_vpc_endpoint" "consumer_vpc_endpoint" {
    vpc_endpoint_type   = aws_vpc_endpoint_service.eks_service.service_type
    service_name        = aws_vpc_endpoint_service.eks_service.service_name
    route_table_ids     = [aws_route_table.vpc2_private_rt.id]
    subnet_ids          = [aws_subnet.vpc2_private[0].id]
    vpc_id              = aws_vpc.vpc2.id
    security_group_ids  = [aws_security_group.ec2_sg.id]
    private_dns_enabled = true
    tags = {
    Name = "consumer-vpc-endpoint"
  }
}

# Create a VPC Endpoint Connection Notification in VPC 2 to connect to the VPC Endpoint in VPC 1
resource "aws_vpc_endpoint_connection_notification" "consumer_vpc_endpoint_connection_notification" {
  connection_notification_arn = "arn:aws:sns:us-east-1:123456789012:MySNSTopic"
  vpc_endpoint_id             = aws_vpc_endpoint.consumer_vpc_endpoint.id
  connection_events           = ["Accept", "Reject", "Terminate"]
}

# Create a VPC Endpoint Route in VPC 2 to connect to the VPC Endpoint in VPC 1
resource "aws_route" "consumer_vpc_endpoint_route" {
  route_table_id         = aws_route_table.vpc2_private_rt.id
  destination_cidr_block = aws_vpc_endpoint_service.eks_service.private_dns_name
  vpc_endpoint_id        = aws_vpc_endpoint.consumer_vpc_endpoint.id
}

# Create a VPC Endpoint Load Balancer Listener Rule in VPC 1 to connect to the VPC Endpoint Service
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

# EC2 Instance in VPC 2 (Consumer VPC)
resource "aws_instance" "consumer_ec2" {
  ami           = "ami-01816d07b1128cd2d"  
  instance_type = "t2.micro"
  subnet_id     = aws_subnet.vpc2_private[0].id
  key_name      = "my-key-pair"    
  iam_instance_profile = aws_iam_instance_profile.ec2_instance_profile.id

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

# IAM Role for EC2 Instance
resource "aws_iam_role" "vpc_ec2_role" {
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
