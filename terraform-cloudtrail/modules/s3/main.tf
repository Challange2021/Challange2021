resource "aws_s3_bucket" "main" {
  bucket        = var.s3_bucket_name
  tags          = var.tags
  force_destroy = var.force_destroy
}
resource "aws_s3_bucket" "logging" {
  bucket = var.name_logging_bucket
  acl    = "private"

  logging {
    target_bucket = aws_s3_bucket.main.id
    target_prefix = "log/"
  }
}
resource "aws_s3_bucket_policy" "default" {
  bucket = aws_s3_bucket.main.id
  policy = data.aws_iam_policy_document.default.json
}

# https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html
data "aws_iam_policy_document" "default" {
  statement {
    sid    = "AWSCloudTrailAclCheck"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:GetBucketAcl",
    ]

    resources = [
      "arn:aws:s3:::${var.s3_bucket_name}",
    ]
  }

  statement {
    sid    = "AWSCloudTrailWrite"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }

    actions = [
      "s3:PutObject",
    ]

    resources = [
      "arn:aws:s3:::${var.s3_bucket_name}/*",
    ]

    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"

      values = [
        "bucket-owner-full-control",
      ]
    }
  }
}