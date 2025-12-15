resource "aws_sns_topic" "s3_replication_alerts" {
  name = "s3-replication-alerts"
}

module "bucket_1" {
  # ...

  dr_enabled                      = true
  dr_bidirectional                = true
  dr_mrap_enabled                 = true
  dr_replication_time_control     = true
  dr_replication_alert_topic_arn  = aws_sns_topic.s3_replication_alerts.arn
}
