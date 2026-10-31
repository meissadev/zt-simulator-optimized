# Infrastructure de mesure AWS du simulateur PQC-Zero Trust (v2).
#
# Cree, dans deux regions (eventuellement identiques) :
#   * une instance "serveur" qui heberge l'architecture (PKI, IdP, PDP, PEP,
#     Ressource) et expose les ports 18443/18444/18447 ;
#   * une instance "client" qui execute le banc de mesure contre le serveur ;
#   * un groupe de securite par instance, ouvert uniquement a l'operateur
#     (operator_cidr) et a l'autre instance ;
#   * la paire de cles SSH (cle publique fournie par l'operateur).
#
# Types par defaut eligibles a l'offre gratuite (free tier). Toutes les
# ressources portent le tag Project=<project> ; `terraform destroy` les
# supprime toutes.
#
#   terraform init
#   terraform apply -var operator_cidr=$(curl -s https://checkip.amazonaws.com)/32 \
#                   -var ssh_public_key_file=~/.ssh/ztpqc_aws.pub
#   terraform output -json > ../../results/aws-hosts.json
#   terraform destroy ...   (memes variables)

terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  alias   = "server"
  region  = var.server_region
  profile = var.aws_profile
  default_tags { tags = { Project = var.project } }
}

provider "aws" {
  alias   = "client"
  region  = var.client_region
  profile = var.aws_profile
  default_tags { tags = { Project = var.project } }
}

# ------------------------------------------------------------- images AMI --
data "aws_ami" "ubuntu_server" {
  provider    = aws.server
  most_recent = true
  owners      = ["099720109477"] # Canonical
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
}

data "aws_ami" "ubuntu_client" {
  provider    = aws.client
  most_recent = true
  owners      = ["099720109477"]
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"]
  }
}

data "aws_vpc" "server" {
  provider = aws.server
  default  = true
}

data "aws_vpc" "client" {
  provider = aws.client
  default  = true
}

# ------------------------------------------------------------- cles SSH ----
resource "aws_key_pair" "server" {
  provider   = aws.server
  key_name   = "${var.project}-server"
  public_key = file(pathexpand(var.ssh_public_key_file))
}

resource "aws_key_pair" "client" {
  provider   = aws.client
  key_name   = "${var.project}-client"
  public_key = file(pathexpand(var.ssh_public_key_file))
}

# ------------------------------------------------------------- instances ---
locals {
  user_data = <<-EOT
    #!/bin/bash
    set -e
    apt-get update -q
    apt-get install -y -q docker.io docker-compose-v2 docker-buildx zstd git python3
    usermod -aG docker ubuntu
    systemctl enable --now docker
    touch /var/tmp/ready
  EOT
}

resource "aws_instance" "server" {
  provider               = aws.server
  ami                    = data.aws_ami.ubuntu_server.id
  instance_type          = var.server_instance_type
  key_name               = aws_key_pair.server.key_name
  vpc_security_group_ids = [aws_security_group.server.id]
  user_data              = local.user_data
  root_block_device {
    volume_size           = var.server_volume_gb
    volume_type           = "gp3"
    delete_on_termination = true
  }
  tags = { Name = "${var.project}-server" }
}

resource "aws_instance" "client" {
  provider               = aws.client
  ami                    = data.aws_ami.ubuntu_client.id
  instance_type          = var.client_instance_type
  key_name               = aws_key_pair.client.key_name
  vpc_security_group_ids = [aws_security_group.client.id]
  user_data              = local.user_data
  root_block_device {
    volume_size           = var.client_volume_gb
    volume_type           = "gp3"
    delete_on_termination = true
  }
  tags = { Name = "${var.project}-client" }
}

# ------------------------------------------------- groupes de securite ----
# Les regles qui referencent l'autre instance sont separees pour eviter une
# dependance circulaire (adresse IP publique connue apres creation).

resource "aws_security_group" "server" {
  provider    = aws.server
  name        = "${var.project}-server"
  description = "ZT-PQC bench server (temporaire)"
  vpc_id      = data.aws_vpc.server.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "client" {
  provider    = aws.client
  name        = "${var.project}-client"
  description = "ZT-PQC bench client (temporaire)"
  vpc_id      = data.aws_vpc.client.id
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

locals {
  server_ports = [22, 18443, 18444, 18447]
}

resource "aws_vpc_security_group_ingress_rule" "server_operator" {
  provider          = aws.server
  for_each          = toset([for p in local.server_ports : tostring(p)])
  security_group_id = aws_security_group.server.id
  cidr_ipv4         = var.operator_cidr
  ip_protocol       = "tcp"
  from_port         = tonumber(each.value)
  to_port           = tonumber(each.value)
}

resource "aws_vpc_security_group_ingress_rule" "server_from_client" {
  provider          = aws.server
  for_each          = toset([for p in local.server_ports : tostring(p)])
  security_group_id = aws_security_group.server.id
  cidr_ipv4         = "${aws_instance.client.public_ip}/32"
  ip_protocol       = "tcp"
  from_port         = tonumber(each.value)
  to_port           = tonumber(each.value)
}

resource "aws_vpc_security_group_ingress_rule" "client_operator" {
  provider          = aws.client
  security_group_id = aws_security_group.client.id
  cidr_ipv4         = var.operator_cidr
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
}

resource "aws_vpc_security_group_ingress_rule" "client_from_server" {
  provider          = aws.client
  security_group_id = aws_security_group.client.id
  cidr_ipv4         = "${aws_instance.server.public_ip}/32"
  ip_protocol       = "tcp"
  from_port         = 22
  to_port           = 22
}
