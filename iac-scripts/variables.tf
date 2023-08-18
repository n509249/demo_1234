
######################################
###        S3                    ###
######################################
variable s3 {
  type = list(object({
    bucket_name        = string,
    versioning_enabled = bool,
    encryption_enabled = bool,
    lifecycle_rules = list(object({
      rule_name                          = string,
      enabled                            = bool,
      expiration_days                    = number,
      noncurrent_version_expiration_days = number
    })),
    bucket_policy = object({
      iam_role_list_permission   = list(string),
      iam_role_read_permission   = list(string),
      iam_role_write_permission  = list(string),
      iam_role_delete_permission = list(string),
      iam_user_list_permission   = list(string),
      iam_user_read_permission   = list(string),
      iam_user_write_permission  = list(string),
      iam_user_delete_permission = list(string),
      read_prefix                = list(string),
      write_prefix               = list(string),
      delete_prefix              = list(string)
    }),
    s3_cors_rule=object({
      allowed_methods = list(string),
      allowed_origins = list(string)
    })
    s3_tags = map(string)
  }))
}


######################################
###        Common Variables        ###
######################################
variable "tags" {
  type    = map(string)
  default = {}
}