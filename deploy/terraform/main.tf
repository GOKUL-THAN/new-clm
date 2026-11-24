terraform {
  required_version = ">= 1.5.0"
  required_providers {
    clm = {
      source  = "example.com/clm/clm"
      version = "~> 1.0"
    }
  }
}

provider "clm" {
  endpoint = "https://clm.example.com"
  token    = var.clm_api_token
}

variable "clm_api_token" {
  type        = string
  sensitive   = true
  description = "Scoped automation token for CLM control plane"
}

resource "clm_environment" "aws_prod" {
  name   = "aws-prod"
  type   = "aws"
  region = "us-east-1"
  tags   = ["pci-dss", "prod"]
}

resource "clm_certificate_profile" "prod_web_tls" {
  name                 = "prod-web-tls"
  validity_days_max    = 90
  allowed_cas          = ["letsencrypt", "digicert"]
  algorithms           = ["ECDSA-P256", "RSA-2048"]
  allowed_san_patterns = [".example.com"]
  allow_wildcards      = false
  require_approval     = true
  caa_enforce          = true
}

resource "clm_certificate_request" "api_cert" {
  profile_id     = clm_certificate_profile.prod_web_tls.id
  environment_id = clm_environment.aws_prod.id
  common_name    = "api.example.com"
  sans           = ["api.example.com", "www.example.com"]
  owner          = "team-platform"
  team           = "platform"
}
