# Nightly refresh (ATT&CK, intel, KB sync, baselines, retention) and detection over
# events pushed to HEC every 15 minutes, as one-off Fargate tasks.
data "aws_iam_policy_document" "scheduler_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["scheduler.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "scheduler" {
  name               = "${var.name}-scheduler"
  assume_role_policy = data.aws_iam_policy_document.scheduler_assume.json
}

resource "aws_iam_role_policy" "scheduler" {
  role = aws_iam_role.scheduler.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["ecs:RunTask"], Resource = [aws_ecs_task_definition.job.arn_without_revision, "${aws_ecs_task_definition.job.arn_without_revision}:*"] },
      { Effect = "Allow", Action = ["iam:PassRole"], Resource = [aws_iam_role.execution.arn, aws_iam_role.task.arn] },
    ]
  })
}

locals {
  jobs = {
    refresh = { cron = "cron(15 3 * * ? *)", command = ["refresh"] }
    detect  = { cron = "rate(15 minutes)", command = ["run", "--from-db", "--since", "25h"] }
  }
}

resource "aws_scheduler_schedule" "job" {
  for_each            = local.jobs
  name                = "${var.name}-${each.key}"
  schedule_expression = each.value.cron
  flexible_time_window { mode = "OFF" }
  target {
    arn      = aws_ecs_cluster.main.arn
    role_arn = aws_iam_role.scheduler.arn
    ecs_parameters {
      task_definition_arn = aws_ecs_task_definition.job.arn
      launch_type         = "FARGATE"
      network_configuration {
        subnets         = aws_subnet.private[*].id
        security_groups = [aws_security_group.app.id]
      }
    }
    input = jsonencode({ containerOverrides = [{ name = "job", command = each.value.command }] })
  }
}
