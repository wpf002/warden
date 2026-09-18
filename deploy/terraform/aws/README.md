# Warden on AWS

ECS Fargate behind an ALB (HTTPS, optional OIDC sign-in), RDS Postgres, EFS for the
knowledge base and vector index, Secrets Manager, CloudWatch logs, and EventBridge
Scheduler for the nightly refresh and the 15-minute detection run.

```bash
cd deploy/terraform/aws
terraform init
terraform apply -var certificate_arn=arn:aws:acm:...           # add -var-file with oidc={...} for SSO
# push the image to the repository it created
aws ecr get-login-password | docker login --username AWS --password-stdin $(terraform output -raw ecr_repository | cut -d/ -f1)
docker build -t $(terraform output -raw ecr_repository):0.7.0 ../../.. && docker push $(terraform output -raw ecr_repository):0.7.0
# put the API key in the app secret, then roll the service
aws secretsmanager put-secret-value --secret-id $(terraform output -raw app_secret) --secret-string '{"WARDEN_DATABASE_URL":"<keep>","ANTHROPIC_API_KEY":"sk-ant-..."}'
aws ecs update-service --cluster warden --service warden --force-new-deployment
```

Notes
- Without `oidc`, the app runs `WARDEN_AUTH=basic`; set `WARDEN_USERS` in the secret.
- With `oidc`, every signed-in user gets `default_role`. Mapping IdP groups to roles
  needs the claims in `x-amzn-oidc-data` verified; that is not implemented yet.
- `enable_aws_response` grants the task only the calls the aws_nacl and aws_iam
  connectors make. Actions still run dry until `WARDEN_LIVE_ACTIONS=1`.
- Validated with `terraform validate`; not yet applied to a live account.
