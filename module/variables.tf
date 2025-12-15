variable "dr_replication_alert_topic_arn" {
  description = "SNS topic ARN for DR replication CloudWatch alarms (optional)"
  type        = string
  default     = null
}
