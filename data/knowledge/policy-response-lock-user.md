# Response policy RP-002: lock_user

- Always requires analyst approval (SEC-012 §2). Never auto-executes regardless of risk.
- The target must be a user named in the alert or incident evidence.
- Locking means: disable sign-in, revoke sessions and refresh tokens, require a password reset.
- Never lock service accounts automatically; coordinate with the owning team to rotate instead.
- Rollback: re-enable the account. The password reset requirement stays.
