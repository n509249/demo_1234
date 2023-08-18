variable "create_s3_bucket" {
  description = "Controls if s3 bucket and associated resources are created"
  type        = bool
  default     = true
}

variable "bucket_name" {
  description = "The name of the bucket. Must be less than or equal to 63 characters in length"
  type        = string
  default     = ""
}

variable "tags" {
  description = "A map of tags to assign to the bucket"
  type        = map(string)
  default     = {}
}

variable "versioning_enabled" {
  description = ""
  type        = bool
  default     = true
}

variable "server_side_encryption" {
  description = ""
  type        = bool
  default     = true
}

variable "bucket_policy" {
  type = object({
    iam_role_list_permission   = list(string),
    iam_role_read_permission   = list(string),
    iam_role_write_permission  = list(string),
    iam_role_delete_permission = list(string),
    iam_user_list_permission   = list(string),
    iam_user_read_permission   = list(string),
    iam_user_write_permission  = list(string),
    iam_user_delete_permission = list(string),
    #appflow_write_permission   = list(string),
    read_prefix                = list(string),
    write_prefix               = list(string),
    delete_prefix              = list(string)
  })
  default = {
  iam_role_list_permission     = [],
    iam_role_read_permission   = [],
    iam_role_write_permission  = [],
    iam_role_delete_permission = [],
    iam_user_list_permission   = [],
    iam_user_read_permission   = [],
    iam_user_write_permission  = [],
    iam_user_delete_permission = [],
    #appflow_write_permission   = [],
    read_prefix                = [],
    write_prefix               = [],
    delete_prefix              = []
  }
}

variable lifecycle_rules {
  type    = list(object({ rule_name = string, enabled = bool, expiration_days = number, noncurrent_version_expiration_days = number }))
  default = []
}

variable "iam_role_name" {
  description = "Name of the IAM role"
  type        = string
  default     = ""
}

variable "create_bucket_policy" {
  type    = bool
  default = true
}

variable "sftp_server_accountid" {
  type    = string
  default = ""
}

variable "sftp_source_bucket" {
  type    = string
  default = ""
}

variable "sftp_user_iam_role" {
  type    = string
  default = ""
}

variable "s3_cors_rule" {
  type = object({
    allowed_methods = list(string),
    allowed_origins = list(string)
  })
  default = {
    allowed_methods = [],
    allowed_origins = []
  }
}

variable "other_bucket_permission_role" {
  type    = list(string)
  default = []
}

variable "sftp_other_bucket_permission_role" {
  type    = list(string)
  default = []
}