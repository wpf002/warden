# Response policy RP-005: disable_access_key

- Automatable when risk >= 80: deactivating a key is reversible and does not delete it.
- The target principal must appear in the alert evidence.
- Rollback: reactivate the key.
