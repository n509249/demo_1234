#############################################################################################
## Creates a S3 bucket with dynamic setting of versioning, encryption and lifecycle rules
#############################################################################################
resource "aws_s3_bucket" "s3_bucket" {
  count  = var.create_s3_bucket ? 1 : 0
  bucket = var.bucket_name

  versioning {
    enabled = var.versioning_enabled
  }

  dynamic "server_side_encryption_configuration" {
    for_each = var.server_side_encryption ? [1] : []
    content {
      rule {
        apply_server_side_encryption_by_default {
          sse_algorithm = "AES256"
        }
      }
    }
  }

  dynamic "lifecycle_rule" {
    for_each = toset(var.lifecycle_rules)
    content {
      id      = lifecycle_rule.value.rule_name
      enabled = lifecycle_rule.value.enabled

      dynamic expiration {
        for_each = lifecycle_rule.value.expiration_days > 0 ? [1] : []
        content {
          days = lifecycle_rule.value.expiration_days
        }
      }

      dynamic noncurrent_version_expiration {
        for_each = lifecycle_rule.value.noncurrent_version_expiration_days > 0 ? [1] : []
        content {
          days = lifecycle_rule.value.noncurrent_version_expiration_days
        }
      }

    }
  }

  dynamic "cors_rule" {
    for_each = length(var.s3_cors_rule.allowed_methods) == 0 && length(var.s3_cors_rule.allowed_origins) == 0 ? [] : [1]
    content {
      allowed_methods = var.s3_cors_rule.allowed_methods
      allowed_origins = var.s3_cors_rule.allowed_origins
    }
  }
  
  force_destroy = true
  tags          = var.tags
}


###################################################################
## Manages S3 bucket-level Public Access Block configuration
###################################################################
resource "aws_s3_bucket_public_access_block" "s3_bucket_access" {
  depends_on              = [aws_s3_bucket.s3_bucket]
  count                   = var.create_s3_bucket ? 1 : 0
  bucket                  = aws_s3_bucket.s3_bucket[count.index].id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}


##################################################
## Attaches a policy to an S3 bucket resource
##################################################
resource "aws_s3_bucket_policy" "b" {
  depends_on = [aws_s3_bucket_public_access_block.s3_bucket_access]
  count      = var.create_bucket_policy ? 1 : 0
  bucket     = aws_s3_bucket.s3_bucket[count.index].id
  policy     = data.aws_iam_policy_document.policy.json
}


############################################
## Data to create IAM policy dynamically
############################################
data "aws_iam_policy_document" "policy" {
  version = "2012-10-17"
  dynamic "statement" {
    for_each = (length(var.bucket_policy.iam_role_list_permission) != 0 && !contains(var.bucket_policy.iam_role_list_permission, "*")) || (length(var.bucket_policy.iam_user_list_permission) != 0 && !contains(var.bucket_policy.iam_user_list_permission, "*")) ? [1] : []
    content {
      sid    = "ListBucketPermission"
      effect = "Deny"
      principals {
        identifiers = ["*"]
        type        = "*"
      }
      actions   = ["s3:ListBucket"]
      resources = ["arn:aws:s3:::${var.bucket_name}"]
      condition {
        test = "StringNotEquals"
        values = concat(["arn:aws:iam::${local.account_id}:role/IAGAdmin", "arn:aws:iam::${local.account_id}:role/github-oidc-stafftravel-role", "arn:aws:iam::${local.account_id}:role/IAGPowerUser"],
          [for list_permission in var.bucket_policy.iam_role_list_permission : "arn:aws:iam::${local.account_id}:role/${list_permission}"],[for new-user in var.bucket_policy.iam_user_list_permission : "arn:aws:iam::${local.account_id}:user/${new-user}"],
        local.isSFTPAvailable ? ["arn:aws:iam::${var.sftp_server_accountid}:role/${var.sftp_user_iam_role}"] : [])
        variable = "aws:PrincipalArn"
      }
    }
  }

  dynamic "statement" {
    for_each = (length(var.bucket_policy.iam_role_read_permission) != 0 && !contains(var.bucket_policy.iam_role_read_permission, "*")) || (length(var.bucket_policy.iam_user_read_permission) != 0 && !contains(var.bucket_policy.iam_user_read_permission, "*")) ? [1] : []
    content {
      sid    = "ReadBucketPermission"
      effect = "Deny"
      principals {
        identifiers = ["*"]
        type        = "*"
      }
      actions   = [
        "s3:GetObject", 
        "s3:GetObjectTagging", 
        "s3:GetObjectVersionTagging"
        ]
      resources = length(var.bucket_policy.read_prefix) == 0 ? ["arn:aws:s3:::${var.bucket_name}/*"] : [for read_prefix in var.bucket_policy.read_prefix : "arn:aws:s3:::${var.bucket_name}/${read_prefix}/*"]
      condition {
        test = "StringNotEquals"
        values = concat([for read_permission in var.bucket_policy.iam_role_read_permission : "arn:aws:iam::${local.account_id}:role/${read_permission}"],[for new-user in var.bucket_policy.iam_user_read_permission : "arn:aws:iam::${local.account_id}:user/${new-user}"],
        local.isSFTPAvailable ? ["arn:aws:iam::${var.sftp_server_accountid}:role/${var.sftp_user_iam_role}"] : [])
        variable = "aws:PrincipalArn"
      }
    }
  }

  dynamic "statement" {
    for_each = (length(var.bucket_policy.iam_role_write_permission) != 0 && !contains(var.bucket_policy.iam_role_write_permission, "*")) || (length(var.bucket_policy.iam_user_write_permission) != 0 && !contains(var.bucket_policy.iam_user_write_permission, "*")) ? [1] : []
    content {
      sid    = "WriteBucketPermission"
      effect = "Deny"
      principals {
        identifiers = ["*"]
        type        = "*"
      }
      actions   = [
        "s3:PutObject", 
        "s3:PutObjectTagging", 
        "s3:PutObjectVersionTagging",
        "s3:PutBucketCORS"
        ]
      resources = length(var.bucket_policy.write_prefix) == 0 ? ["arn:aws:s3:::${var.bucket_name}/*", "arn:aws:s3:::${var.bucket_name}"] : concat([for write_prefix in var.bucket_policy.write_prefix : "arn:aws:s3:::${var.bucket_name}/${write_prefix}/*"], ["arn:aws:s3:::${var.bucket_name}"])
      condition {
        test = "StringNotEquals"
        values = concat([for write_permission in var.bucket_policy.iam_role_write_permission : "arn:aws:iam::${local.account_id}:role/${write_permission}"],[for new-user in var.bucket_policy.iam_user_write_permission : "arn:aws:iam::${local.account_id}:user/${new-user}"],
          local.isSFTPAvailable ? ["arn:aws:iam::${var.sftp_server_accountid}:role/${var.sftp_user_iam_role}"] : [], ["arn:aws:iam::${local.account_id}:role/IAGAdmin", "arn:aws:iam::${local.account_id}:role/github-oidc-stafftravel-role"])
        variable = "aws:PrincipalArn"
      }
    }
  }

  dynamic "statement" {
    for_each = (length(var.bucket_policy.iam_role_delete_permission) != 0 && !contains(var.bucket_policy.iam_role_delete_permission, "*")) || (length(var.bucket_policy.iam_user_delete_permission) != 0 && !contains(var.bucket_policy.iam_user_delete_permission, "*")) ? [1] : [] 
    content {
      sid    = "DeleteBucketPermission"
      effect = "Deny"
      principals {
        identifiers = ["*"]
        type        = "*"
      }
      actions   = ["s3:DeleteObject"]
      resources = length(var.bucket_policy.delete_prefix) == 0 ? ["arn:aws:s3:::${var.bucket_name}/*"] : [for delete_prefix in var.bucket_policy.delete_prefix : "arn:aws:s3:::${var.bucket_name}/${delete_prefix}/*"]
      condition {
        test = "StringNotEquals"
        values = concat([for delete_permission in var.bucket_policy.iam_role_delete_permission : "arn:aws:iam::${local.account_id}:role/${delete_permission}"],[for new-user in var.bucket_policy.iam_user_delete_permission : "arn:aws:iam::${local.account_id}:user/${new-user}"],[
          "arn:aws:iam::${local.account_id}:role/IAGAdmin",
          "arn:aws:iam::${local.account_id}:role/github-oidc-stafftravel-role"
        ])
        variable = "aws:PrincipalArn"
      }
    }
  }

  dynamic "statement" {
    for_each = local.isSFTPAvailable ? [1] : []
    content {
      sid    = "WriteBucketPermissionFromSFTP"
      effect = "Allow"
      principals {
        identifiers = ["arn:aws:iam::${var.sftp_server_accountid}:root"]
        type        = "AWS"
      }
      actions = [
        "s3:PutObject",
        "s3:ListBucket",
        "s3:PutObjectAcl",
        "s3:GetObject"
      ]
      resources = [
        "arn:aws:s3:::${var.sftp_source_bucket}",
        "arn:aws:s3:::${var.sftp_source_bucket}/*"
      ]
      condition {
        test     = "StringEquals"
        values   = ["arn:aws:iam::${var.sftp_server_accountid}:role/${var.sftp_user_iam_role}"]
        variable = "aws:PrincipalArn"
      }
    }
  }

  dynamic "statement" {
    for_each = length(var.bucket_policy.iam_role_list_permission) == 0 && length(var.bucket_policy.iam_role_read_permission) == 0 && length(var.bucket_policy.iam_role_write_permission) == 0 && length(var.bucket_policy.iam_role_delete_permission) == 0 && length(var.bucket_policy.iam_user_list_permission) == 0 && length(var.bucket_policy.iam_user_read_permission) == 0 && length(var.bucket_policy.iam_user_write_permission) == 0 && length(var.bucket_policy.iam_user_delete_permission) == 0 ? [] : [1]
    content {
      sid    = "OtherBucketPermissions"
      effect = "Deny"
      principals {
        identifiers = ["*"]
        type        = "*"
      }
      not_actions = concat(
        length(var.bucket_policy.iam_role_list_permission) != 0 ? ["s3:ListBucket"] : [],
        length(var.bucket_policy.iam_role_read_permission) != 0 ? ["s3:GetObject", "s3:GetObjectTagging", "s3:GetObjectVersionTagging"] : [],
        length(var.bucket_policy.iam_role_write_permission) != 0 ? ["s3:PutObject", "s3:PutObjectTagging", "s3:PutObjectVersionTagging", "s3:PutBucketCORS"] : [],
        length(var.bucket_policy.iam_role_delete_permission) != 0 ? ["s3:DeleteObject"] : [],
        length(var.bucket_policy.iam_user_list_permission) != 0 ? ["s3:ListBucket"] : [],
        length(var.bucket_policy.iam_user_read_permission) != 0 ? ["s3:GetObject", "s3:GetObjectTagging", "s3:GetObjectVersionTagging"] : [],
        length(var.bucket_policy.iam_user_write_permission) != 0 ? ["s3:PutObject", "s3:PutObjectTagging", "s3:PutObjectVersionTagging"] : [],
        length(var.bucket_policy.iam_user_delete_permission) != 0 ? ["s3:DeleteObject"] : [],
        local.isSFTPAvailable ? ["s3:PutObjectAcl"] : []
        

      )

      resources = [
        "arn:aws:s3:::${var.bucket_name}", "arn:aws:s3:::${var.bucket_name}/*",
        "arn:aws:s3:::${var.bucket_name}", "arn:aws:s3:::${var.bucket_name}"
      ]
      condition {
        test = "StringNotEquals"
        values = concat([for other_bucket_permission in var.other_bucket_permission_role : "arn:aws:iam::${local.account_id}:role/${other_bucket_permission}"],
        [for sftp_other_bucket_permission in var.sftp_other_bucket_permission_role : "arn:aws:iam::${var.sftp_server_accountid}:role/${sftp_other_bucket_permission}"],
        ["arn:aws:iam::${local.account_id}:role/IAGAdmin",
          "arn:aws:iam::${local.account_id}:role/github-oidc-stafftravel-role"
        ])
        variable = "aws:PrincipalArn"
      }
    }
  }

  dynamic "statement" {
    for_each = length(var.bucket_policy.iam_role_list_permission) == 0 && length(var.bucket_policy.iam_role_read_permission) == 0 && length(var.bucket_policy.iam_role_write_permission) == 0 && length(var.bucket_policy.iam_role_delete_permission) == 0 && length(var.bucket_policy.iam_user_list_permission) == 0 && length(var.bucket_policy.iam_user_read_permission) == 0 && length(var.bucket_policy.iam_user_write_permission) == 0 && length(var.bucket_policy.iam_user_delete_permission) == 0 && ! local.isSFTPAvailable ? [1] : []
    content {
      sid    = "OtherBucketPermissions"
      effect = "Deny"
      principals {
        identifiers = ["*"]
        type        = "*"
      }
      not_actions = [
        "s3:GetBucketLocation",
        "s3:GetObject",
        "s3:ListBucket",
        "s3:ListBucketMultipartUploads",
        "s3:ListMultipartUploadParts",
        "s3:AbortMultipartUpload",
        "s3:PutObject"
      ]
      resources = [
        "arn:aws:s3:::${var.bucket_name}", "arn:aws:s3:::${var.bucket_name}/*",
        "arn:aws:s3:::${var.bucket_name}", "arn:aws:s3:::${var.bucket_name}"
      ]
      condition {
        test = "StringNotEquals"
        values = concat(["arn:aws:iam::${local.account_id}:role/IAGAdmin",
          "arn:aws:iam::${local.account_id}:role/github-oidc-stafftravel-role"
          ])
        variable = "aws:PrincipalArn"
      }
    }
  }

  statement {
    sid    = "AllowSSLRequestsOnly"
    effect = "Deny"
    principals {
      identifiers = ["*"]
      type        = "*"
    }
    actions = ["s3:*"]
    resources = [
      "arn:aws:s3:::${var.bucket_name}", "arn:aws:s3:::${var.bucket_name}/*",
      "arn:aws:s3:::${var.bucket_name}", "arn:aws:s3:::${var.bucket_name}"
    ]
    condition {
      test     = "Bool"
      values   = ["false"]
      variable = "aws:SecureTransport"
    }
  }
/*dynamic "statement" {
    for_each = (length(var.bucket_policy.appflow_write_permission) != 0 && !contains(var.bucket_policy.appflow_write_permission, "*")) ? [1] : []
    content {
      sid    = "AppflowWritePermission"
      effect = "Deny"
      principals {
        identifiers = ["*"]
        type        = "*"
      }
      actions   = [
        "s3:putobject",
        "s3:getbucketacl", 
        "s3:putobjectacl"
        ]
      resources = length(var.bucket_policy.write_prefix) == 0 ? ["arn:aws:s3:::${var.bucket_name}/*", "arn:aws:s3:::${var.bucket_name}"] : concat([for write_prefix in var.bucket_policy.write_prefix : "arn:aws:s3:::${var.bucket_name}/${write_prefix}/*"], ["arn:aws:s3:::${var.bucket_name}"])
      condition {
        test = "StringNotEquals"
        values = concat([for appflow_permission in var.bucket_policy.appflow_write_permission : "arn:aws:iam::${local.account_id}:role/${appflow_permission}"])
        variable = "aws:PrincipalArn"
      }
    }
  }
*/
}

data "aws_caller_identity" "current" {}

locals {
  account_id      = data.aws_caller_identity.current.account_id
  isSFTPAvailable = (var.bucket_name == var.sftp_source_bucket) && var.sftp_server_accountid != "" && var.sftp_source_bucket != "" && var.sftp_user_iam_role != "" && var.sftp_user_iam_role != "*"
}
