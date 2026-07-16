
# DevSecOps Auto Ticket Notification Service

Xay dung backend service tu dong polling findings tu DefectDojo va gui email notification den email ticket tuong ung. Service chay scheduler dinh ky moi 5 phut de call DefectDojo API lay danh sach findings co trang thai `active=true` va `verified=true`.

## Tech Stack

- Language: Python
- Runtime server: Uvicorn
- Database: PostgreSQL
- Email transport: SMTP with TLS/authentication
- Scheduler: internal application scheduler
- Queue/rate limit storage: PostgreSQL
- Prometheus metrics: khong nam trong scope hien tai

## Source Code Organization

Code chinh cua application nam trong folder `src`.

```text
src/
    __init__.py
    main.py
    config.py
    logging_config.py
    database.py
    models.py
    schemas.py
    repositories.py
    scheduler.py
    processor.py
    defectdojo_client.py
    email_template.py
    smtp_client.py
    rate_limiter.py
    retry.py
    health.py
```

File responsibilities:

- `main.py`: Uvicorn application entrypoint, init app lifecycle, start/stop scheduler.
- `config.py`: load va validate environment variables.
- `logging_config.py`: setup structured application logging.
- `database.py`: PostgreSQL connection/session setup.
- `models.py`: database models cho processing log, queue va rate limit state.
- `schemas.py`: internal data schemas cho DefectDojo finding, email payload va processing status.
- `repositories.py`: database access layer cho finding log, queue, status update va audit query.
- `scheduler.py`: dinh ky trigger polling DefectDojo va queue processing theo `SCHEDULER_INTERVAL_SECONDS`.
- `processor.py`: orchestration xu ly finding end-to-end: duplicate check, validation, rate limit, retry va status update.
- `defectdojo_client.py`: client call DefectDojo API, handle auth, timeout va pagination.
- `email_template.py`: generate DevSecOps security alert subject/body.
- `smtp_client.py`: SMTP connection, TLS/authentication, timeout va send email.
- `rate_limiter.py`: DB-backed SMTP rate limit theo minute/hour quota.
- `retry.py`: tinh retry delay va xac dinh transient SMTP error.
- `health.py`: health check endpoint cho application/runtime.

Uvicorn target:

```bash
uvicorn main:app --app-dir src
```

## Main Flow

1. Scheduler chay moi 5 phut.
2. Service call DefectDojo API lay findings `active=true` va `verified=true`.
3. Voi tung finding, he thong kiem tra duplicate dua tren `finding_id`.
4. Neu finding da ton tai voi trang thai `SENT` thi bo qua va log event duplicate skipped.
5. Neu finding chua ton tai hoac dang co trang thai `FAILED` thi tiep tuc xu ly o schedule hien tai.
6. He thong mapping data tu DefectDojo sang email payload.
7. He thong generate enterprise security alert email subject/body.
8. He thong kiem tra SMTP rate limit.
9. Neu vuot rate limit thi dua email vao queue luu trong PostgreSQL, gan trang thai `RATE_LIMITED`, tuyet doi khong drop email.
10. Neu con quota thi gui email qua SMTP.
11. Neu gui thanh cong thi cap nhat trang thai `SENT`.
12. Neu SMTP fail tam thoi thi retry theo exponential backoff.
13. Neu vuot qua retry toi da thi cap nhat trang thai `FAILED`.

## DefectDojo API Sample

Trong giai doan dau, DefectDojo API detail duoc dung theo sample sau de build integration truoc. Neu response thuc te khac sample, mapping se duoc dieu chinh sau.

Request:

```http
GET {DEFECTDOJO_BASE_URL}/api/v2/findings/?active=true&verified=true&limit=100&offset=0
Authorization: Token {DEFECTDOJO_API_TOKEN}
Accept: application/json
```

Sample response:

```json
{
  "count": 1,
  "next": null,
  "previous": null,
  "results": [
    {
      "id": 12345,
      "title": "SQL Injection",
      "severity": "Critical",
      "description": "SQL injection vulnerability in login endpoint.",
      "impact": "Attackers may read or modify application data.",
      "mitigation": "Use parameterized queries and validate input.",
      "date": "2026-05-27",
      "active": true,
      "verified": true,
      "product": {
        "id": 10,
        "name": "Customer Portal"
      },
      "endpoints": [
        {
          "host": "app.example.com",
          "path": "/login"
        }
      ],
      "ticket_email": "security-ticket@example.com"
    }
  ]
}
```

Pagination can duoc xu ly bang field `next` hoac bang `limit/offset` neu `next` co gia tri `null`.

## Field Mapping

Thong tin tu DefectDojo can mapping sang email payload:

| Email payload field | DefectDojo sample field |
| --- | --- |
| `finding_id` | `results[].id` |
| `title` | `results[].title` |
| `severity` | `results[].severity` |
| `description` | `results[].description` |
| `impact` | `results[].impact` |
| `mitigation` | `results[].mitigation` |
| `product` | `results[].product.name` |
| `endpoint` | join tu `results[].endpoints[].host` + `path` |
| `date` | `results[].date` |
| `ticket_email` | `results[].ticket_email` |

Recipient email priority:

1. Uu tien `results[].ticket_email` neu co va dung format email.
2. Neu `ticket_email` rong hoac khong dung format, lookup theo `product` trong project email mapping JSON.
3. Neu khong tim duoc email hop le, he thong cap nhat trang thai `INVALID_RECIPIENT` va khong gui SMTP.

Project email mapping JSON format:

```json
{
  "projects": [
    {
      "project_name": "Customer Portal Security",
      "product_name": "Customer Portal",
      "email_destinations": [
        "security-ticket@example.com",
        "customer-portal-owner@example.com"
      ]
    },
    {
      "project_name": "Payment Security",
      "product_name": "Payment Service",
      "email_destinations": [
        "payment-security-ticket@example.com",
        "payment-service-owner@example.com"
      ]
    }
  ]
}
```

Sample file nam tai `config/project_email_mapping.sample.json`.

## Email Template

Vi day la du an DevSecOps, email subject can giu branding DevSecOps/security alert.

Subject format:

```text
[DevSecOps Security Alert][{Severity}] Finding #{finding_id} - {title}
```

Example:

```text
[DevSecOps Security Alert][Critical] Finding #12345 - SQL Injection
```

Email body can chua day du thong tin de team nhan email co the xu ly ngay:

- Finding ID
- Title
- Severity
- Product
- Endpoint
- Date
- Description
- Impact
- Mitigation

## SMTP

Service gui email qua SMTP server den `ticket_email` hoac danh sach email dich duoc resolve tu project email mapping.

SMTP can ho tro:

- TLS
- Authentication
- Timeout handling
- Connection pooling

## Rate Limit

He thong can ap dung SMTP rate limit de tranh bi block boi mail provider.

Default config:

- `max_emails_per_minute=30`
- `max_emails_per_hour=500`

Rate limit state va queue phai duoc luu trong PostgreSQL de system co the recover sau restart. Neu vuot rate limit, email phai duoc dua vao queue cho gui va danh dau trang thai `RATE_LIMITED`, khong duoc drop email.

Scheduler o cac lan chay tiep theo can uu tien xu ly lai cac item dang `RATE_LIMITED` khi quota SMTP cho phep.

## Retry Logic

Retry wording:

- `max_attempts=3` nghia la tong cong toi da 3 lan gui SMTP cho mot processing cycle.
- Attempt 1: gui ngay.
- Attempt 2: retry sau 60 giay neu attempt 1 fail do loi tam thoi.
- Attempt 3: retry sau 120 giay neu attempt 2 fail do loi tam thoi.

Loi SMTP tam thoi gom:

- Timeout
- Connection reset
- Temporary unavailable
- SMTP 4xx transient error

Sau khi vuot qua `max_attempts=3`, he thong cap nhat trang thai `FAILED`.

Neu finding co trang thai `FAILED`, scheduler lan tiep theo van duoc phep xu ly lai finding do khi DefectDojo van tra ve finding `active=true` va `verified=true`.

## Database Logging And Audit

Toan bo qua trinh xu ly can duoc luu vao PostgreSQL de phuc vu audit va troubleshooting.

Bang processing log can co cac field:

- `finding_id`
- `recipient_email`
- `email_subject`
- `status`
- `retry_count`
- `error_message`
- `processed_at`
- `created_at`
- `updated_at`

Can tao unique index cho `finding_id` de dam bao duplicate prevention.

Status xu ly gom:

- `PENDING`: waiting process
- `SENT`: email sent successfully
- `FAILED`: failed after max retry
- `SKIPPED`: duplicate finding skipped
- `RATE_LIMITED`: waiting queue
- `INVALID_RECIPIENT`: invalid email

Duplicate rule:

- Neu `finding_id` da ton tai voi status `SENT`, khong gui lai email.
- Duplicate skipped event can duoc log vao application log.
- Neu `finding_id` ton tai voi status `FAILED`, scheduler lan tiep theo se cap nhat record hien co va thu gui lai.
- Neu `finding_id` ton tai voi status `RATE_LIMITED`, scheduler tiep tuc giu trong DB queue va gui khi quota cho phep.

## Configuration

Application can ho tro configuration thong qua environment variables.

DefectDojo:

- `DEFECTDOJO_BASE_URL`
- `DEFECTDOJO_API_TOKEN`
- `DEFECTDOJO_FINDINGS_LIMIT`
- `DEFECTDOJO_REQUEST_TIMEOUT_SECONDS`

Project email mapping:

- `PROJECT_EMAIL_MAPPING_JSON`: inline JSON object map project/product name sang mot hoac nhieu email dich.
- `PROJECT_EMAIL_MAPPING_FILE`: path den JSON file map project/product name sang mot hoac nhieu email dich.

Neu ca 2 bien deu duoc cau hinh, `PROJECT_EMAIL_MAPPING_JSON` se override key trung voi file.

PostgreSQL:

- `DATABASE_URL`

SMTP:

- `SMTP_HOST`
- `SMTP_PORT`
- `SMTP_USERNAME`
- `SMTP_PASSWORD`
- `SMTP_FROM_EMAIL`
- `SMTP_USE_TLS`
- `SMTP_TIMEOUT_SECONDS`
- `SMTP_POOL_SIZE`

Scheduler:

- `SCHEDULER_INTERVAL_SECONDS` default `300`

Rate limit:

- `SMTP_MAX_EMAILS_PER_MINUTE` default `30`
- `SMTP_MAX_EMAILS_PER_HOUR` default `500`

Retry:

- `SMTP_MAX_ATTEMPTS` default `3`
- `SMTP_RETRY_DELAY_SECONDS` default `60`
- `SMTP_RETRY_BACKOFF_MULTIPLIER` default `2`

## Application Logs

He thong can log cac event quan trong:

- Scheduler start/end
- DefectDojo API call failed
- Finding fetched
- Invalid recipient
- Duplicate skipped
- Rate limit triggered
- Email queued
- SMTP send failed
- Retry scheduled
- Email sent
- Processing status updated

## Spec Review

README hien tai da du ro de bat dau build code skeleton va core flow. Mot so thong tin van nen chot them truoc khi deploy production:

- Migration tool cho PostgreSQL: Alembic hay SQL script thu cong.
- Exact DefectDojo response thuc te cho field `ticket_email`, `product` va `endpoints`.
- SMTP provider rule thuc te: quota, TLS mode, sender policy va allowed recipient domain.
- Deployment format: Docker, systemd hay chay truc tiep bang Uvicorn.
- API audit endpoint co can authentication hay chi expose noi bo.

## Implementation Steps

5 buoc thuc hien yeu cau:

1. Tao Python project structure trong `src/`, load config tu environment variables va expose FastAPI/Uvicorn app kem health endpoint.
2. Tao PostgreSQL models/tables cho processing log, queue/rate limit state, unique index theo `finding_id` va repository layer de audit/update status.
3. Build DefectDojo client theo sample API, xu ly auth, timeout, pagination va mapping response sang internal finding/email payload schemas.
4. Build email pipeline gom template DevSecOps security alert, validate recipient, duplicate prevention, DB-backed rate limit queue va SMTP send voi TLS/authentication.
5. Build scheduler orchestration va retry logic: poll moi 5 phut, uu tien xu ly `RATE_LIMITED`, retry transient SMTP error voi `max_attempts=3`, cho phep `FAILED` duoc xu ly lai o lan polling sau.

## Acceptance Criteria

- Scheduler chay moi 5 phut.
- Chi lay findings `active=true` va `verified=true`.
- DefectDojo integration build theo sample API truoc.
- Khong gui duplicate email cho finding da `SENT`.
- Finding `FAILED` duoc schedule tiep o lan polling sau.
- Generate dung DevSecOps security alert email template.
- SMTP rate limit hoat dong dung config.
- Rate limit queue duoc luu trong PostgreSQL.
- Retry SMTP fail hoat dong dung logic voi `max_attempts=3`.
- Co processing log day du trong PostgreSQL.
- Co the audit trang thai xu ly cua tung finding.
- System recover sau restart.
- Configurable qua environment variables.
- Khong can expose Prometheus metrics trong scope hien tai.