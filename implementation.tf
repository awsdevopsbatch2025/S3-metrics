only for first bucket creation you need to create resource and pass it as  dr_replication_alert_topic_arn  = aws_sns_topic.s3_replication_alerts.arn

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


#########################################################################################################################################################################################################

from second bucket we juts need to read that resource like below 

data "aws_sns_topic" "s3_replication_alerts" {
  name = "s3-replication-alerts"
}

module "bucket_2" {
  # ...

  dr_enabled                      = true
  dr_bidirectional                = true
  dr_mrap_enabled                 = true
  dr_replication_time_control     = true
  dr_replication_alert_topic_arn  = data.aws_sns_topic.s3_replication_alerts.arn
}
