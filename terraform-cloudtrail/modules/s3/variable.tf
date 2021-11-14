variable "s3_bucket_name" {
  type        = string
  default     = "s3_bucket"
  description = "Name of s3 bucket"
}
variable "tags" {
  description = "Tags for s3 bucket"
}
variable "force_destroy" {
  type        = bool
  default     = false
  description = "Force destroy values"
}
variable "name_logging_bucket" {
  type        = string
  default     = ""
  description = "Name of the loggin bucket"
}
