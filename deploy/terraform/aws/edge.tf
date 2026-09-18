resource "aws_lb" "app" {
  name                       = var.name
  load_balancer_type         = "application"
  subnets                    = aws_subnet.public[*].id
  security_groups            = [aws_security_group.alb.id]
  drop_invalid_header_fields = true
}

resource "aws_lb_target_group" "app" {
  name        = var.name
  port        = 8000
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"
  health_check {
    path    = "/healthz"
    matcher = "200"
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.app.arn
  port              = 80
  protocol          = "HTTP"
  default_action {
    type = "redirect"
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.app.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.certificate_arn

  # With OIDC configured the ALB signs users in and forwards x-amzn-oidc-identity,
  # which Warden trusts (WARDEN_AUTH=proxy) because only the ALB can reach the tasks.
  dynamic "default_action" {
    for_each = nonsensitive(var.oidc == null) ? toset([]) : toset(["oidc"])
    content {
      type  = "authenticate-oidc"
      order = 1
      authenticate_oidc {
        issuer                 = var.oidc.issuer
        authorization_endpoint = var.oidc.authorization_endpoint
        token_endpoint         = var.oidc.token_endpoint
        user_info_endpoint     = var.oidc.user_info_endpoint
        client_id              = var.oidc.client_id
        client_secret          = var.oidc.client_secret
      }
    }
  }
  default_action {
    type             = "forward"
    order            = 2
    target_group_arn = aws_lb_target_group.app.arn
  }
}

# The HEC receiver authenticates by token, so forwarders bypass the OIDC sign-in.
resource "aws_lb_listener_rule" "hec" {
  listener_arn = aws_lb_listener.https.arn
  priority     = 10
  condition {
    path_pattern { values = ["/services/collector/*"] }
  }
  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.app.arn
  }
}
