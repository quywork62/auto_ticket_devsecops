# Database Setup and Schema



## Nguyên tắc chính

- Docker Compose mặc định tự tạo PostgreSQL database/user từ biến `POSTGRES_DB`, `POSTGRES_USER`, `POSTGRES_PASSWORD`.
- Alembic là nguồn tạo/cập nhật table chính. Không tạo table thủ công bằng SQL riêng.
- FastAPI startup không tự tạo table.
- Không commit password thật. Trong tài liệu/log/report luôn redact secret thành `XXXXXX`.

## Database và user mặc định

| Mục | Giá trị mặc định |
|---|---|
| Database | `devsecops` |
| App role/user | `devsecops` |
| PostgreSQL version | `16` |
| SQLAlchemy URL | `postgresql+psycopg://devsecops:XXXXXX@postgres:5432/devsecops` |

Trong `docker-compose.prod.yml`, Postgres container dùng:

```yaml
POSTGRES_DB: devsecops
POSTGRES_USER: devsecops
POSTGRES_PASSWORD: ${POSTGRES_PASSWORD}
```

Nếu dùng PostgreSQL bên ngoài Docker, chạy bootstrap bằng admin user:

```bash
psql -h <postgres-host> -U postgres -d postgres \
  -v app_db=devsecops \
  -v app_user=devsecops \
  -f db/01_bootstrap_database.sql
```

Script sẽ hỏi password cho `devsecops`.

## Quyền cần cấp

Role `devsecops` cần quyền cho migration và runtime:

| Scope | Quyền | Lý do |
|---|---|---|
| Database `devsecops` | `CONNECT`, `TEMPORARY` | App/migration kết nối DB |
| Schema `public` | `USAGE`, `CREATE` | Alembic tạo table, enum type, index |
| Tables runtime | `SELECT`, `INSERT`, `UPDATE`, `DELETE` | App đọc/ghi audit, retry, queue |
| Sequences runtime | `USAGE`, `SELECT`, `UPDATE` | Insert vào bảng có integer primary key |
| Enum types | `USAGE` | Dùng `processing_status`, `notification_status` |

Với deploy hiện tại, cùng một role `devsecops` chạy cả `migrate` và `app`, nên role này cần `CREATE` trên schema `public`. Nếu sau này tách riêng migration role và runtime role, runtime role có thể bỏ `CREATE` sau khi migration xong.

Áp lại grant sau migration nếu DBA sở hữu object:

```bash
psql -h <postgres-host> -U postgres -d devsecops \
  -v app_db=devsecops \
  -v app_user=devsecops \
  -f db/02_runtime_grants.sql
```

## Chạy migration

Docker production:

```bash
docker compose -f docker-compose.prod.yml up -d postgres
docker compose -f docker-compose.prod.yml run --rm migrate
docker compose -f docker-compose.prod.yml run --rm migrate alembic current
```

Kỳ vọng version:

```text
20260629_0003 (head)
```

## Kiểm tra schema

Trong Docker:

```bash
docker compose -f docker-compose.prod.yml exec -T postgres \
  psql -U devsecops -d devsecops -f /dev/stdin < db/03_verify_schema.sql
```

Với PostgreSQL bên ngoài Docker:

```bash
psql -h <postgres-host> -U devsecops -d devsecops \
  -v app_user=devsecops \
  -f db/03_verify_schema.sql
```

## Tables hiện tại

### `processing_logs`

Mục đích: lưu trạng thái xử lý mới nhất cho mỗi DefectDojo finding, dùng để chống duplicate và audit ticket/email.

| Column | Type | Nullable | Ghi chú |
|---|---|---:|---|
| `id` | integer | no | Primary key |
| `finding_id` | integer | no | DefectDojo finding ID, unique |
| `dedupe_key` | varchar(80) | yes | Key chống duplicate logic |
| `ticket_id` | varchar(120) | yes | ManageEngine request/ticket ID nếu có |
| `ticket_status` | varchar(80) | yes | Trạng thái ticket nếu có |
| `last_seen_at` | timestamptz | yes | Lần gần nhất finding được thấy |
| `seen_count` | integer | no | Số lần gặp lại finding |
| `priority` | varchar(80) | yes | Priority map từ severity |
| `sla_target` | varchar(80) | yes | SLA target theo mapper |
| `sla_due_at` | timestamptz | yes | Deadline SLA nếu có |
| `recipient_email` | varchar(320) | yes | Recipient chính được ghi lại |
| `email_subject` | varchar(500) | yes | Subject email |
| `email_body` | text | yes | Plain text email body |
| `email_html_body` | text | yes | HTML email body |
| `status` | `processing_status` | no | `PENDING`, `SENT`, `FAILED`, `SKIPPED`, `RATE_LIMITED`, `INVALID_RECIPIENT` |
| `retry_count` | integer | no | Số lần retry |
| `next_attempt_at` | timestamptz | yes | Lịch retry tiếp theo |
| `error_message` | text | yes | Lỗi đã redact |
| `processed_at` | timestamptz | yes | Thời điểm xử lý xong |
| `created_at` | timestamptz | no | Thời điểm tạo row |
| `updated_at` | timestamptz | no | Thời điểm cập nhật row |

Indexes/constraints:

- Primary key: `id`
- Unique: `uq_processing_logs_finding_id` on `finding_id`
- Indexes: `finding_id`, `dedupe_key`, `ticket_id`, `status`, `next_attempt_at`

### `notification_deliveries`

Mục đích: queue/retry từng notification email theo từng recipient.

| Column | Type | Nullable | Ghi chú |
|---|---|---:|---|
| `id` | integer | no | Primary key |
| `finding_id` | integer | no | DefectDojo finding ID |
| `dedupe_key` | varchar(80) | no | Key chống duplicate |
| `recipient_email` | varchar(320) | no | Người/group nhận notification |
| `cc_emails` | text | yes | Danh sách CC dạng text |
| `email_subject` | varchar(500) | no | Subject email |
| `email_body` | text | no | Plain text body |
| `email_html_body` | text | yes | HTML body |
| `status` | `notification_status` | no | `PENDING`, `SENT`, `RETRY_PENDING`, `FAILED` |
| `retry_count` | integer | no | Số lần retry |
| `next_attempt_at` | timestamptz | yes | Lịch retry tiếp theo |
| `error_message` | text | yes | Lỗi đã redact |
| `lease_owner` | varchar(36) | yes | Worker đang giữ delivery |
| `lease_expires_at` | timestamptz | yes | Hết hạn lease |
| `sent_at` | timestamptz | yes | Thời điểm gửi thành công |
| `created_at` | timestamptz | no | Thời điểm tạo row |
| `updated_at` | timestamptz | no | Thời điểm cập nhật row |

Indexes/constraints:

- Primary key: `id`
- Unique: `uq_notification_delivery_finding_recipient` on `finding_id`, `recipient_email`
- Indexes: `finding_id`, `dedupe_key`, `status`, `next_attempt_at`, `lease_expires_at`

### `smtp_send_events`

Mục đích: audit immutable cho mỗi lần SMTP gửi thành công.

| Column | Type | Nullable | Ghi chú |
|---|---|---:|---|
| `id` | integer | no | Primary key |
| `finding_id` | integer | yes | DefectDojo finding ID nếu liên quan |
| `recipient_email` | varchar(320) | no | Người nhận |
| `cc_emails` | text | yes | CC nếu có |
| `flow_type` | varchar(80) | yes | Ví dụ `ticket_email`, `notify_email` |
| `delivery_mode` | varchar(40) | yes | `email_fetch` hoặc `api` |
| `sent_at` | timestamptz | no | Thời điểm gửi thành công |

Indexes:

- Primary key: `id`
- Indexes: `finding_id`, `flow_type`, `sent_at`

### `alembic_version`

Mục đích: Alembic tracking migration version.

| Column | Type | Nullable | Ghi chú |
|---|---|---:|---|
| `version_num` | varchar(32) | no | Current migration revision |

## Migrations

| Revision | Mục đích |
|---|---|
| `20260625_0001` | Baseline `processing_logs`, `smtp_send_events`, enum `processing_status` |
| `20260625_0002` | Thêm `email_html_body`, `next_attempt_at`, `notification_deliveries`, enum `notification_status` |
| `20260629_0003` | Xoá bảng `dedupe_claims` |

## Lưu ý vận hành

- Không expose PostgreSQL port ra internet. Compose hiện chỉ bind `127.0.0.1:5432`.
- Không truncate `alembic_version` khi clear data test.
- Nếu reset data test, chỉ truncate `notification_deliveries`, `smtp_send_events`, `processing_logs`.
- Trước khi bật tạo ticket thật, giữ `MANAGEENGINE_DRY_RUN=true` để kiểm tra DB/log trước.
