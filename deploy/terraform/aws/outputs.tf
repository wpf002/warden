output "url" { value = "https://${aws_lb.app.dns_name}" }
output "ecr_repository" { value = aws_ecr_repository.warden.repository_url }
output "app_secret" { value = aws_secretsmanager_secret.app.name }
output "log_group" { value = aws_cloudwatch_log_group.app.name }
