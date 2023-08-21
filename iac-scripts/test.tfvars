######################################
###           s3                   ###
######################################
s3 = [{
  bucket_name        = "demo-123456"
  versioning_enabled = true
  encryption_enabled = false
  lifecycle_rules    = []
  s3_tags            = {}
  bucket_policy = {
    iam_role_list_permission   = []
    iam_role_read_permission   = []
    iam_role_write_permission  = []
    iam_role_delete_permission = []
    iam_user_list_permission   = []
    iam_user_read_permission   = []
    iam_user_write_permission  = []
    iam_user_delete_permission = []
    read_prefix                = []
    write_prefix               = []
    delete_prefix              = []
  }
  s3_cors_rule = {
    allowed_methods = [],
    allowed_origins = []
  }
}]
