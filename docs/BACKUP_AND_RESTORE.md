# Backup and restore

The database and application secret are one backup unit. A database without its matching secret cannot decrypt provider credentials, webhook secrets, or TOTP secrets.

## SQLite backup

Stop the panel and worker or otherwise pause writes. Copy these files together:

```text
instance/domain-oss.db
instance/secret_key
```

For Docker, snapshot or copy the `domain_oss_data` volume while application writes are stopped.

## MySQL backup

Use a transactionally consistent dump supported by your MySQL deployment. Back up the external `SECRET_KEY` at the same time. Database users, TLS keys, and server configuration are outside the application and must be covered by the database operator's process.

## Restore procedure

1. Provision the same or a compatible application version.
2. Restore the database and matching secret.
3. Set all deployment environment variables.
4. Run `./panel upgrade`.
5. Run `./panel doctor`.
6. Start the panel and one worker.
7. Test administrator login, provider health, one DNS write, email delivery, and webhooks.
8. Re-enable normal traffic and additional workers.

Test restores on an isolated host. A backup is not verified until the restored application can decrypt credentials and publish a temporary DNS record.
