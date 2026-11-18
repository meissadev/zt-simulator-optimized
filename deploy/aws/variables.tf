variable "project" {
  description = "Prefixe des noms et valeur du tag Project"
  type        = string
  default     = "ztpqc-bench"
}

variable "aws_profile" {
  description = "Profil AWS CLI utilise"
  type        = string
  default     = "default"
}

variable "server_region" {
  description = "Region du serveur (architecture)"
  type        = string
  default     = "eu-west-2"
}

variable "client_region" {
  description = "Region du client de mesure (identique au serveur pour un test intra-region)"
  type        = string
  default     = "us-east-1"
}

variable "server_instance_type" {
  description = "Type d'instance du serveur (eligible free tier : c7i-flex.large, t3.small, ...)"
  type        = string
  default     = "c7i-flex.large"
}

variable "client_instance_type" {
  description = "Type d'instance du client de mesure"
  type        = string
  default     = "t3.small"
}

variable "server_volume_gb" {
  type    = number
  default = 20
}

variable "client_volume_gb" {
  type    = number
  default = 12
}

variable "operator_cidr" {
  description = "Adresse de l'operateur autorisee en SSH et sur les ports du banc (ex. 203.0.113.7/32)"
  type        = string
}

variable "ssh_public_key_file" {
  description = "Cle publique SSH installee sur les instances (cle sans phrase de passe pour l'automatisation)"
  type        = string
  default     = "~/.ssh/ztpqc_aws.pub"
}
