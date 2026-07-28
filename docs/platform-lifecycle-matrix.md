# Production platform lifecycle matrix

This matrix defines the packaged `signet setup` platform contract. Every row is
exercised with fake providers or service-manager command doubles in CI; it does not
claim a real host, Tailnet, Hermes profile, browser ceremony, or provider was changed.

| Dimension | Variant | Expected result | Automated evidence |
|---|---|---|---|
| Host service manager | macOS launchd user agents | Separate loopback MCP and web agents; `Umask=077`, throttled restart, bounded file descriptors, private logs | `tests/test_setup_platform_sp23.py`, `tests/test_setup.py` |
| Host service manager | Linux systemd user units | Separate loopback MCP and web units; restart throttling, `MemoryMax`, `TasksMax`, `LimitNOFILE`, private umask | `tests/test_setup_platform_sp23.py`, `tests/test_setup.py` |
| Worker topology | provider rollout disabled | Web lifespan owns bounded recovery, policy publication, retention, notification-outbox, log, and cache maintenance; provider delivery remains blocked | `tests/test_production.py` |
| Worker topology | reviewed provider rollout enabled | The same web lifespan additionally owns delivery/reconciliation and exact provider sessions; startup and shutdown update durable health | `tests/test_production.py`, `tests/test_production_connectors.py` |
| Storage layout | default | Database and backups use `ROOT/data` and `ROOT/backups`; staging, restore, cache, and logs remain private siblings | `tests/test_setup.py`, `tests/test_setup_platform_sp23.py` |
| Storage layout | external data | Setup requires a pre-created empty mode-0700 directory and binds matching internal/external markers plus exact `st_dev` | `tests/test_setup_platform_sp23.py`, `tests/test_setup_cli.py` |
| Storage layout | external backups | Setup marker-binds a pre-created empty mode-0700 backup root; uninstall/purge preserves reviewed recovery bundles and key material | `tests/test_setup_platform_sp23.py`, `tests/test_lifecycle_plans.py` |
| Capacity | warning | Below 4 GiB or 15% free, plan/apply emits an actionable warning without exposing secret data | `tests/test_setup_platform_sp23.py` |
| Capacity | hard reserve | Below 1 GiB + 100 MiB attachment batch + 25 MiB rotation, setup fails before mutation | `tests/test_setup_platform_sp23.py` |
| Retention | logs/cache/staging/backups | Logs copy-truncate at 25 MiB with one rotation, cache prunes oldest-first at 1 GiB, staging admission stays at 50 MiB, and backups refuse growth above 8 GiB | `tests/test_storage_lifecycle.py`, `tests/test_staging.py`, `tests/test_lifecycle_plans.py` |
| Private HTTPS | derived Tailscale origin | Setup manages only the reviewed HTTPS 8443 Serve listener and refuses conflicts/Funnel; rollback removes only exact owned state | `tests/test_setup.py` |
| Hermes | one or many named profiles | Each profile receives exact disabled MCP blocks and a separate token reference; rollback removes only exact owned edits and never restarts Hermes | `tests/test_setup.py`, `tests/test_setup_cli.py` |
| Lifecycle | backup/restore | Plan then exact apply; encrypted bundle verification and restore go to a new staging tree, never over active state | `tests/test_lifecycle_plans.py` |
| Lifecycle | upgrade | Plan then exact apply; quiesce, verified pre-migration backup, schema migration, durable receipt, restart or fail closed | `tests/test_setup.py`, `tests/test_lifecycle_plans.py` |
| Lifecycle | uninstall/purge | Normal uninstall preserves data; purge requires a verified backup and preserves its recovery material; rollback is marker-bound and resumable | `tests/test_setup.py`, `tests/test_lifecycle_plans.py` |
| Recovery | interruption or drift | Journals, owner markers, receipts, identity checks, and exact plan IDs make retries resumable and reject changed/foreign state | `tests/test_setup.py`, `tests/test_setup_cli.py` |

## Release verification

From a reviewed checkout using Python 3.12 with SQLite 3.51.3 or newer:

```console
uv sync --frozen
uv run pytest -q
uv run ruff check .
uv run mypy
uv build
```

Inspect a read-only packaged plan on each target host before apply:

```console
signet setup --plan
signet status
signet doctor
```

For an external data volume, review the effective path and device number in the plan,
then physically disconnect or remount only in a disposable test environment and prove
that preflight refuses the changed identity. Never perform that drill against active
production data.
