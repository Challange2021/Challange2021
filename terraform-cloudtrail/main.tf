data "aws_regions" "current" {}
module "cloudtrail" {
  source                        = "./modules/cloudtrail"
  s3_bucket_name                = module.s3.output.id
  is_multi_region_trail         = true
  enable_log_file_validation    = true
  include_global_service_events = true
  include_management_events     = true
  email= "mas2794@outlook.com"
}
module "s3" {
  source         = "./modules/s3"
  s3_bucket_name = "amin.s2394bucket"
  tags = {
    Name        = "My bucket"
    Environment = "Dev"

  }
  force_destroy       = true
  name_logging_bucket = "amin.s2394"
}