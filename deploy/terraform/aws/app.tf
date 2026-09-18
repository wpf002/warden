resource "aws_ecr_repository" "warden" {
  name                 = var.name
  image_tag_mutability = "IMMUTABLE"
  image_scanning_configuration { scan_on_push = true }
}

resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/${var.name}"
  retention_in_days = 90
}

resource "aws_ecs_cluster" "main" {
  name = var.name
  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

# ---------------------------------------------------------------- IAM
data "aws_iam_policy_document" "ecs_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "execution" {
  name               = "${var.name}-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy_attachment" "execution" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_secrets" {
  role = aws_iam_role.execution.id
  policy = jsonencode({
    Version   = "2012-10-17"
    Statement = [{ Effect = "Allow", Action = ["secretsmanager:GetSecretValue"], Resource = [aws_secretsmanager_secret.app.arn] }]
  })
}

resource "aws_iam_role" "task" {
  name               = "${var.name}-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume.json
}

resource "aws_iam_role_policy" "task_efs" {
  role = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["elasticfilesystem:ClientMount", "elasticfilesystem:ClientWrite"]
      Resource = [aws_efs_file_system.data.arn]
    }]
  })
}

# Only with enable_aws_response: the aws_nacl and aws_iam connectors' exact permissions.
resource "aws_iam_role_policy" "task_response" {
  count = var.enable_aws_response ? 1 : 0
  role  = aws_iam_role.task.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      { Effect = "Allow", Action = ["ec2:DescribeNetworkAcls"], Resource = "*" },
      {
        Effect   = "Allow"
        Action   = ["ec2:CreateNetworkAclEntry", "ec2:DeleteNetworkAclEntry"]
        Resource = "arn:aws:ec2:${var.region}:*:network-acl/${var.response_nacl_id}"
      },
      {
        Effect   = "Allow"
        Action   = ["iam:ListAccessKeys", "iam:UpdateAccessKey", "iam:PutUserPolicy", "iam:DeleteUserPolicy"]
        Resource = "arn:aws:iam::*:user/*"
      },
    ]
  })
}

# ---------------------------------------------------------------- task definition
locals {
  image       = "${aws_ecr_repository.warden.repository_url}:${var.image_tag}"
  secret_keys = ["WARDEN_DATABASE_URL", "ANTHROPIC_API_KEY"]
  environment = [
    { name = "WARDEN_DATA_DIR", value = "/data" },
    { name = "WARDEN_LOG_FORMAT", value = "json" },
    { name = "WARDEN_LLM", value = "anthropic" },
    { name = "WARDEN_MODEL", value = "claude-opus-5" },
    { name = "WARDEN_MODEL_TRIAGE", value = "claude-sonnet-5" },
    { name = "WARDEN_AUTH", value = nonsensitive(var.oidc == null) ? "basic" : "proxy" },
    { name = "WARDEN_PROXY_USER_HEADER", value = "x-amzn-oidc-identity" },
    { name = "WARDEN_PROXY_DEFAULT_ROLE", value = var.default_role },
    { name = "WARDEN_TRUSTED_PROXIES", value = var.vpc_cidr },
    { name = "WARDEN_AWS_NACL_ID", value = var.response_nacl_id },
  ]
  container = {
    image       = local.image
    essential   = true
    environment = local.environment
    secrets     = [for k in local.secret_keys : { name = k, valueFrom = "${aws_secretsmanager_secret.app.arn}:${k}::" }]
    mountPoints = [{ sourceVolume = "data", containerPath = "/data" }]
    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.app.name
        awslogs-region        = var.region
        awslogs-stream-prefix = "warden"
      }
    }
  }
}

resource "aws_ecs_task_definition" "warden" {
  family                   = var.name
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }
  volume {
    name = "data"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.data.id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.data.id
        iam             = "ENABLED"
      }
    }
  }
  container_definitions = jsonencode([merge(local.container, {
    name         = "warden"
    command      = ["serve"]
    portMappings = [{ containerPort = 8000, protocol = "tcp" }]
  })])
}

resource "aws_ecs_task_definition" "job" {
  family                   = "${var.name}-job"
  requires_compatibilities = ["FARGATE"]
  network_mode             = "awsvpc"
  cpu                      = var.task_cpu
  memory                   = var.task_memory
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn
  volume {
    name = "data"
    efs_volume_configuration {
      file_system_id     = aws_efs_file_system.data.id
      transit_encryption = "ENABLED"
      authorization_config {
        access_point_id = aws_efs_access_point.data.id
        iam             = "ENABLED"
      }
    }
  }
  container_definitions = jsonencode([merge(local.container, { name = "job", command = ["refresh"] })])
}

resource "aws_ecs_service" "warden" {
  name            = var.name
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.warden.arn
  desired_count   = 1
  launch_type     = "FARGATE"
  network_configuration {
    subnets         = aws_subnet.private[*].id
    security_groups = [aws_security_group.app.id]
  }
  load_balancer {
    target_group_arn = aws_lb_target_group.app.arn
    container_name   = "warden"
    container_port   = 8000
  }
  health_check_grace_period_seconds = 120
  depends_on                        = [aws_lb_listener.https, aws_efs_mount_target.data]
}
