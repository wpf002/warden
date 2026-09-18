variable "region" {
  type    = string
  default = "us-east-1"
}

variable "env" {
  type    = string
  default = "prod"
}

variable "name" {
  type    = string
  default = "warden"
}

variable "vpc_cidr" {
  type    = string
  default = "10.40.0.0/16"
}

variable "image_tag" {
  description = "Tag of the image pushed to the ECR repository this stack creates."
  type        = string
  default     = "0.7.0"
}

variable "certificate_arn" {
  description = "ACM certificate for the HTTPS listener."
  type        = string
}

variable "oidc" {
  description = "ALB OIDC authentication. Leave null to use WARDEN_AUTH=basic instead."
  type = object({
    issuer                 = string
    authorization_endpoint = string
    token_endpoint         = string
    user_info_endpoint     = string
    client_id              = string
    client_secret          = string
  })
  default   = null
  sensitive = true
}

variable "default_role" {
  description = "Role for users the OIDC proxy signs in (viewer, analyst, admin)."
  type        = string
  default     = "analyst"
}

variable "db_instance_class" {
  type    = string
  default = "db.t4g.small"
}

variable "task_cpu" {
  type    = number
  default = 1024
}

variable "task_memory" {
  type    = number
  default = 3072
}

variable "enable_aws_response" {
  description = "Grant the task the EC2/IAM permissions the aws_nacl and aws_iam connectors need."
  type        = bool
  default     = false
}

variable "response_nacl_id" {
  description = "Network ACL the aws_nacl connector writes deny rules to (when enable_aws_response)."
  type        = string
  default     = ""
}
