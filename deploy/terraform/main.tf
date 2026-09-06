terraform {
  required_version = ">= 1.3"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

locals {
  name        = var.project_name
  ssh_enabled = var.ssh_key_name != ""
  tags        = { Project = var.project_name, ManagedBy = "terraform" }
}

# --- Latest Ubuntu 22.04 LTS AMI (Canonical) ---------------------------------
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"]

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# --- Minimal self-contained network ------------------------------------------
resource "aws_vpc" "ctf" {
  cidr_block           = "10.20.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags                 = merge(local.tags, { Name = "${local.name}-vpc" })
}

resource "aws_internet_gateway" "ctf" {
  vpc_id = aws_vpc.ctf.id
  tags   = merge(local.tags, { Name = "${local.name}-igw" })
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.ctf.id
  cidr_block              = "10.20.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
  tags                    = merge(local.tags, { Name = "${local.name}-public" })
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.ctf.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.ctf.id
  }
  tags = merge(local.tags, { Name = "${local.name}-public-rt" })
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# --- Security group: only allowed_cidr reaches CTFd (:80), the app gate (:8080)
#     and (optionally) SSH. Players still log in at CTFd / the gate on top. -----
resource "aws_security_group" "ctf" {
  name        = "${local.name}-sg"
  description = "Danubius CTF ingress (scoped to allowed_cidr)"
  vpc_id      = aws_vpc.ctf.id

  ingress {
    description = "CTFd platform"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }
  ingress {
    description = "Vulnerable app gate"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }
  dynamic "ingress" {
    for_each = local.ssh_enabled ? [1] : []
    content {
      description = "SSH"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [var.allowed_cidr]
    }
  }
  egress {
    description = "All outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = merge(local.tags, { Name = "${local.name}-sg" })
}

# --- The instance: cloud-init brings up the whole stack + CTFd ----------------
resource "aws_instance" "ctf" {
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  subnet_id                   = aws_subnet.public.id
  vpc_security_group_ids      = [aws_security_group.ctf.id]
  associate_public_ip_address = true
  key_name                    = local.ssh_enabled ? var.ssh_key_name : null

  root_block_device {
    volume_type = "gp3"
    volume_size = var.root_volume_gb
    encrypted   = true
  }

  user_data_replace_on_change = true
  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    repo_url            = var.repo_url
    repo_ref            = var.repo_ref
    week                = var.week
    ctf_name            = var.ctf_name
    ctfd_admin_user     = var.ctfd_admin_user
    ctfd_admin_password = var.ctfd_admin_password
    max_team_size       = var.max_team_size
  })

  tags = merge(local.tags, { Name = "${local.name}-host" })
}

resource "aws_eip" "ctf" {
  instance = aws_instance.ctf.id
  domain   = "vpc"
  tags     = merge(local.tags, { Name = "${local.name}-eip" })
}
