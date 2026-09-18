# ---------------------------------------------------------------- Postgres
resource "random_password" "db" {
  length  = 32
  special = false
}

resource "aws_db_subnet_group" "db" {
  name       = var.name
  subnet_ids = aws_subnet.private[*].id
}

resource "aws_db_instance" "db" {
  identifier                   = var.name
  engine                       = "postgres"
  engine_version               = "16"
  instance_class               = var.db_instance_class
  allocated_storage            = 50
  max_allocated_storage        = 500
  storage_encrypted            = true
  db_name                      = "warden"
  username                     = "warden"
  password                     = random_password.db.result
  db_subnet_group_name         = aws_db_subnet_group.db.name
  vpc_security_group_ids       = [aws_security_group.db.id]
  backup_retention_period      = 14
  deletion_protection          = true
  skip_final_snapshot          = false
  final_snapshot_identifier    = "${var.name}-final"
  performance_insights_enabled = true
}

# ---------------------------------------------------------------- shared data volume
# Knowledge base markdown, the Chroma index, ATT&CK docs. EFS rather than EBS so the API
# service and the scheduled tasks mount the same files.
resource "aws_efs_file_system" "data" {
  encrypted = true
  tags      = { Name = "${var.name}-data" }
}

resource "aws_efs_mount_target" "data" {
  count           = 2
  file_system_id  = aws_efs_file_system.data.id
  subnet_id       = aws_subnet.private[count.index].id
  security_groups = [aws_security_group.efs.id]
}

resource "aws_efs_access_point" "data" {
  file_system_id = aws_efs_file_system.data.id
  posix_user {
    uid = 10001
    gid = 10001
  }
  root_directory {
    path = "/warden"
    creation_info {
      owner_uid   = 10001
      owner_gid   = 10001
      permissions = "750"
    }
  }
}

# ---------------------------------------------------------------- secrets
resource "aws_secretsmanager_secret" "app" { name = "${var.name}/app" }

# Set ANTHROPIC_API_KEY (and ANTHROPIC_WORKSPACE_ID, WARDEN_HEC_TOKENS, connector
# credentials) in this secret after apply; Terraform only seeds the database URL.
resource "aws_secretsmanager_secret_version" "app" {
  secret_id = aws_secretsmanager_secret.app.id
  secret_string = jsonencode({
    WARDEN_DATABASE_URL = "postgresql+psycopg://warden:${random_password.db.result}@${aws_db_instance.db.address}:5432/warden"
    ANTHROPIC_API_KEY   = "set-me"
  })
  lifecycle { ignore_changes = [secret_string] }
}
