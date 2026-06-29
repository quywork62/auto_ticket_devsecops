# DevSecOps Auto Ticket 

Backend service that polls active and verified findings from DefectDojo,
prevents duplicate processing in PostgreSQL, and creates ManageEngine tickets.

Supported delivery modes:

- `email_fetch`: send a ticket email to the mailbox fetched by ManageEngine.
- `api`: call ManageEngine `POST /api/v3/requests` directly.

The current lifecycle is intentionally limited to `CREATE` and `SKIP`.
Automatic update, reopen, and close are outside the current scope.

## Workflow

```text
FastAPI starts
-> APScheduler runs immediately, then every configured interval
-> Fetch DefectDojo findings: active=true, verified=true
-> Normalize finding data
-> Acquire PostgreSQL dedupe lease
-> Check finding_id and dedupe_key
-> Duplicate: SKIP
-> New finding:
   email_fetch:
     -> ticket_email to ManageEngine mailbox
     -> ManageEngine Incoming Mail creates ticket
   api:
     -> POST /api/v3/requests
     -> store returned ticket ID/status
-> Queue one notify_email per configured To recipient
-> Send notification with configured CC recipients
-> Persist audit and retry state in PostgreSQL
```

The scheduler defaults to five minutes:

```env
SCHEDULER_INTERVAL_SECONDS=300
```

Between scheduler cycles, FastAPI and PostgreSQL remain available, but the
backend does not continuously call DefectDojo or SMTP.

## Email Flows

### `email_fetch`

For each new finding:

```text
Ticket email:
  To: ticket_mailbox only
  Cc: none
  Purpose: ManageEngine fetches this mailbox and creates one ticket

Notification email:
  One separate email per to_destinations address
  To: one project/customer recipient
  Cc: cc_destinations
  Purpose: alert relevant teams without creating additional tickets
```

### `api`

```text
Backend -> ManageEngine API -> ticket
Backend -> one notification email per to_destinations address + CC
```

Notification email is sent only after ticket delivery succeeds. API dry-run
results remain `PENDING` and are not treated as successfully created tickets.

## Duplicate and Retry

Duplicate prevention uses:

- `finding_id` for the same DefectDojo record.
- `dedupe_key` for logically equivalent findings.
- This deployment assumes a single app container and single scheduler.

SMTP retry does not use long `sleep()` calls. A temporary failure is persisted:

```text
SMTP failure
-> increment retry_count
-> store next_attempt_at
-> leave the current scheduler cycle
-> retry during the first scheduler cycle after next_attempt_at
```

Default retry configuration:

```env
SMTP_MAX_ATTEMPTS=3
SMTP_RETRY_DELAY_SECONDS=60
SMTP_RETRY_BACKOFF_MULTIPLIER=2
```

With a five-minute scheduler, a delivery eligible after 60 seconds is normally
retried at the next five-minute cycle.

## PostgreSQL Tables

| Table | Purpose |
|---|---|
| `processing_logs` | Latest finding, ticket, status, payload, and retry state |
| `smtp_send_events` | Immutable successful-send audit and SMTP rate-limit data |
| `notification_deliveries` | Per-recipient notification queue and retry state |
| `alembic_version` | Current database migration revision |

Database schema is managed by Alembic:

```text
20260625_0001_baseline
-> 20260625_0002_delivery_queue
-> 20260629_0003_remove_dedupe_claims
```

FastAPI startup does not create or alter tables.

## Source Layout

```text
src/
  main.py                  FastAPI application, logging, lifecycle
  config.py                Validated environment settings
  scheduler.py             Five-minute polling loop
  processor.py             Main orchestration flow
  defectdojo_client.py     DefectDojo API client and normalization
  dedupe.py                Stable SHA-256 dedupe fingerprint
  email_template.py        Adaptive plain-text and HTML ticket content
  smtp_client.py           SMTP TLS delivery and error classification
  manageengine_mapper.py   Severity, priority, SLA, API payload mapping
  manageengine_client.py   ManageEngine v3 API client and response validation
  database.py              SQLAlchemy engine and session factory
  db_models.py             PostgreSQL ORM models
  repositories.py          Audit, leases, queues, retry, rate limiting
  schemas.py               Pydantic data contracts
  redaction.py             Secret masking
  health.py                /health and /health/db

alembic/                   Versioned PostgreSQL migrations
config/project_mapping.json
                            Product routing configuration
scripts/                    Manual one-shot test command
tests/                      Unit tests
```

## Requirements

- Docker Desktop with Docker Compose
- Python 3.13 for local development
- PostgreSQL 16 through Docker Compose
- DefectDojo API read token
- Approved SMTP account
- ManageEngine mailbox for `email_fetch`, or API credentials for `api`

## Initial Setup

```bash
cd /Users/quyph/Documents/Devsecops_auto_ticket

python3 -m venv .venv
.venv/bin/pip install -r requirements-dev.txt

cp .env.example .env
```

Edit `.env` locally. Never commit the real `.env`.

Configure project routing in:

```text
config/project_mapping.json
```

Example without real addresses:

```json
{
  "projects": [
    {
      "product_name": "Customer Portal",
      "ticket_mailbox": "ticket-mailbox@example.com",
      "to_destinations": [
        "customer-group@example.com",
        "devsecops-group@example.com"
      ],
      "cc_destinations": [
        "security-monitoring@example.com"
      ],
      "group": null,
      "category": null,
      "subcategory": null
    }
  ]
}
```

`product_name` must match the product name resolved from DefectDojo.

## Run Unit Tests

```bash
.venv/bin/python -m pytest -q
```

Current local result:

```text
49 passed
```

Unit tests use fake clients and do not require DefectDojo, SMTP, or
ManageEngine to be running.

## GitHub Actions CI/CD

The repository includes [.github/workflows/ci.yml](.github/workflows/ci.yml)
with these jobs:

| Job | Purpose |
|---|---|
| `secret-guard` | Fails if `.env`, private keys, credential JSON files, or common hardcoded token patterns are tracked |
| `unit-tests` | Installs `requirements-dev.txt` and runs `pytest` |
| `docker-build` | Builds the Docker image for branches and pull requests |
| `docker-publish` | Publishes `latest` and commit-SHA image tags to GitHub Container Registry on `main` pushes |

Initial GitHub setup:

1. Create the GitHub repository without initializing it with a README.
2. Add your SSH public key in GitHub account settings.
3. Point the local repository to GitHub:

```bash
git remote set-url origin git@github.com:n21dcvt084-tech/Devsecops_auto_ticket.git
git remote -v
```

4. Confirm secrets are not tracked:

```bash
git check-ignore -v .env
git ls-files -- .env
```

`git ls-files -- .env` must print nothing.

5. Push:

```bash
git push -u origin main
```

The workflow uses GitHub-hosted runners and Docker Buildx. No custom runner is
required for the default build and publish flow.

Runtime secrets such as DefectDojo tokens, SMTP passwords, ManageEngine API
tokens, and database passwords must not be committed. Store deployment/runtime
values in GitHub under:

```text
Settings -> Secrets and variables -> Actions
```

Use repository or environment secrets for production values. Keep local `.env`
only on the machine or server where the service runs.

Published images are stored in GitHub Container Registry:

```text
ghcr.io/n21dcvt084-tech/devsecops_auto_ticket:latest
ghcr.io/n21dcvt084-tech/devsecops_auto_ticket:<commit-sha>
```

## Build and Migrate

Build both application images because Compose stores separate `app` and
`migrate` image names:

```bash
docker compose build app migrate
```

Start PostgreSQL:

```bash
docker compose up -d postgres
docker compose ps
```

Apply migrations:

```bash
docker compose run --rm migrate
```

Check migration revision:

```bash
docker compose run --rm migrate alembic current
```

Expected:

```text
20260625_0002 (head)
```

Check tables:

```bash
docker compose exec -T postgres \
  psql -U devsecops -d devsecops -c "\dt"
```

## Start Application

Warning: starting `app` starts the scheduler immediately. It may call the real
DefectDojo API and send email according to `.env` and project mapping.

```bash
docker compose up -d app
docker compose logs -f app
```

Health endpoints:

- [http://localhost:8000/health](http://localhost:8000/health)
- [http://localhost:8000/health/db](http://localhost:8000/health/db)

The health endpoint returns HTTP `503` when PostgreSQL is unavailable or the
scheduler is stopped.

Stop the scheduler:

```bash
docker compose stop app
```

Changing Python source, dependencies, Dockerfile, Alembic migrations, scripts,
or `config/project_mapping.json` requires rebuilding the affected images.
Changing only `.env` requires container recreation, not image rebuild:

```bash
docker compose up -d --force-recreate app
```

## Safe Database Reset for Testing

Stop the scheduler first:

```bash
docker compose stop app
```

Clear all local workflow and audit state:

```bash
docker compose exec -T postgres \
  psql -U devsecops -d devsecops -c "
  truncate table
    notification_deliveries,
    smtp_send_events,
    processing_logs
  restart identity;
  "
```

Do not truncate `alembic_version`.

## Manual Test: One Product

Prerequisites:

- PostgreSQL is running.
- Migrations are at `20260629_0003`.
- The scheduler app is stopped.
- The product mapping contains approved recipients.
- The target product has at least one Active + Verified finding.

Run one finding:

```bash
docker compose run --rm \
  -e ALLOW_SEND_REAL_FINDING_TO_GMAIL=yes \
  app python scripts/process_active_verified_findings_to_configured_email.py \
  --product-name "demo-dojo" \
  --limit 1
```

The environment variable name is retained as a deliberate real-send safety
confirmation, even when SMTP is Outlook or another provider.

## Manual Test: Multiple Products

Run one finding per product:

```bash
docker compose run --rm \
  -e ALLOW_SEND_REAL_FINDING_TO_GMAIL=yes \
  app python scripts/process_active_verified_findings_to_configured_email.py \
  --product-names "canhvp-demo,check_500,check_threagile,demo-devsecops-project,demo-dojo" \
  --per-product-limit 1
```

Run the same command again without clearing PostgreSQL to test duplicate
prevention.

## Database Checks

Processing status:

```bash
docker compose exec -T postgres \
  psql -U devsecops -d devsecops -c "
  select
    finding_id,
    dedupe_key,
    status,
    seen_count,
    recipient_email,
    ticket_id,
    ticket_status,
    retry_count,
    next_attempt_at,
    left(coalesce(error_message, ''), 160) as error_message,
    updated_at
  from processing_logs
  order by updated_at desc;
  "
```

Notification queue:

```bash
docker compose exec -T postgres \
  psql -U devsecops -d devsecops -c "
  select
    finding_id,
    recipient_email,
    cc_emails,
    status,
    retry_count,
    next_attempt_at,
    sent_at,
    left(coalesce(error_message, ''), 160) as error_message
  from notification_deliveries
  order by updated_at desc;
  "
```

SMTP audit:

```bash
docker compose exec -T postgres \
  psql -U devsecops -d devsecops -c "
  select
    id,
    finding_id,
    flow_type,
    delivery_mode,
    recipient_email,
    cc_emails,
    sent_at
  from smtp_send_events
  order by sent_at desc;
  "
```

Notification queue:

```bash
docker compose exec -T postgres \
  psql -U devsecops -d devsecops -c "
  select
    id,
    finding_id,
    recipient_email,
    status,
    retry_count,
    next_attempt_at,
    sent_at
  from notification_deliveries
  order by updated_at desc;
  "
```

## ManageEngine Configuration

### Email Fetch

```env
MANAGEENGINE_DELIVERY_MODE=email_fetch
MANAGEENGINE_DRY_RUN=true
```

Requirements:

- Incoming Mail must be configured and fetching `ticket_mailbox`.
- SMTP sender must be allowed to send to the ticket mailbox.
- `MANAGEENGINE_PUBLIC_URL` should be a browser-accessible ticket-list URL.
- `MANAGEENGINE_BASE_URL` and API token are not used to create tickets in this
  mode.

Backend SMTP success confirms only that email was accepted by the mail server.
It does not confirm that ManageEngine has fetched the message or created a
ticket.

### API

Safe payload validation:

```env
MANAGEENGINE_DELIVERY_MODE=api
MANAGEENGINE_DRY_RUN=true
MANAGEENGINE_BASE_URL=https://manageengine.example.com
MANAGEENGINE_AUTH_TOKEN=XXXXXX
```

Real ticket creation:

```env
MANAGEENGINE_DELIVERY_MODE=api
MANAGEENGINE_DRY_RUN=false
MANAGEENGINE_BASE_URL=https://manageengine.example.com
MANAGEENGINE_AUTH_TOKEN=XXXXXX
MANAGEENGINE_VERIFY_SSL=true
```

Real API responses must contain a request ID and successful status before the
finding is marked `SENT`.

## Docker Security

The application container:

- Runs as a non-root user.
- Uses a read-only filesystem with `/tmp` as `tmpfs`.
- Drops Linux capabilities.
- Enables `no-new-privileges`.
- Includes an HTTP healthcheck.

PostgreSQL container port `5432` is bound to local host port `5432`.

For production, replace default database credentials, use a managed secret
store, enable valid TLS certificates, and do not expose PostgreSQL publicly.
