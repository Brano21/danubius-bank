variable "region" {
  description = "AWS region to deploy into."
  type        = string
  default     = "eu-central-1"
}

variable "project_name" {
  description = "Name prefix for all resources / tags."
  type        = string
  default     = "danubius-ctf"
}

variable "instance_type" {
  description = "EC2 size. The Week-3 LLM (Ollama 3B) + the app + CTFd need RAM; 32 GB is comfortable. Drop to m5.large and set week<=2 for a cheap web-only lab."
  type        = string
  default     = "m5.2xlarge"
}

variable "root_volume_gb" {
  description = "Root EBS size (GB). Holds docker images + the Ollama model."
  type        = number
  default     = 60
}

variable "allowed_cidr" {
  description = "CIDR allowed to reach the CTF (SSH + CTFd + the app gate). Set this to YOUR IP (e.g. 203.0.113.7/32) so the lab is not exposed to the whole internet. Players still authenticate at CTFd / the gate on top of this."
  type        = string
  # no default on purpose - you must scope it. Use x.x.x.x/32 for a single IP.
}

variable "ssh_key_name" {
  description = "Name of an EXISTING EC2 key pair for SSH. Leave empty to disable SSH (deploy is fully cloud-init driven)."
  type        = string
  default     = ""
}

variable "repo_url" {
  description = "Git URL of this repository (cloned on the instance at boot). Must be reachable without interactive auth (public, or embed a token)."
  type        = string
  default     = "https://github.com/Brano21/danubius-bank.git"
}

variable "repo_ref" {
  description = "Git branch/tag/commit to deploy."
  type        = string
  default     = "master"
}

variable "week" {
  description = "WEEK to unlock (1-4). 4 = full lab. Use 2 for a cheap web+API-only run (no LLM)."
  type        = number
  default     = 4
}

variable "ctf_name" {
  description = "Title shown in CTFd."
  type        = string
  default     = "Danubius Bank CTF"
}

variable "ctfd_admin_user" {
  description = "CTFd admin username (created automatically)."
  type        = string
  default     = "ctfadmin"
}

variable "ctfd_admin_password" {
  description = "CTFd admin password. CHANGE THIS. Marked sensitive."
  type        = string
  sensitive   = true
}

variable "max_team_size" {
  description = "Max players per team in CTFd (solo play = a team of 1). The brief asks for up to 3."
  type        = number
  default     = 3
}
