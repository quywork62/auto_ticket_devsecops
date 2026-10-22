# DevSecOps Auto Ticket Notification Service

Dịch vụ tự động lấy security findings từ DefectDojo, chống gửi thông báo trùng, định tuyến người nhận theo product và gửi email qua SMTP. Ứng dụng chạy nền theo chu kỳ bằng APScheduler, cung cấp health check bằng FastAPI và lưu trạng thái xử lý trong PostgreSQL.

## Chức năng chính

### Giới hạn vận hành sau refactor

Chạy một app replica; chưa có distributed lock. Finding chỉ `SENT` khi tất cả
delivery thành công; còn delivery chờ thì trạng thái `RATE_LIMITED`, hết chờ
nhưng có delivery lỗi thì `FAILED`. FAILED là terminal, không tự reset retry.
Lỗi DB sau SMTP thành công dừng cycle, không bị coi là SMTP retry; cần kiểm tra
delivery/log vì vẫn có khả năng gửi trùng sau restart hoặc cycle kế tiếp.
HTML hiện chưa được lưu qua queue nên email thực tế là plain text.
Cấu hình timeout/interval/quota/attempt phải dương, port 1–65535 và sender phải
là email hợp lệ. Biến lease TTL cũ không còn hiệu lực. Phân trang findings chỉ
chấp nhận cùng origin/path, không theo redirect hay trang lặp.

Test an toàn, không đọc `.env` và không gửi email:

```bash
PYTHONPATH=src .venv/bin/python -B -m unittest discover -s tests -v
```

- Lấy các finding đang `active=true` và `verified=true` từ DefectDojo API.
- Chỉ lấy finding của các product được khai báo trong project mapping.
- Hỗ trợ phân trang khi DefectDojo trả về nhiều kết quả.
- Chuẩn hóa finding cho SAST, DAST, dependency và cloud security.
- Chống gửi trùng theo `finding_id` và người nhận.
- Tạo email dạng plain text và HTML.
- Che token, API key, mật khẩu và dữ liệu nhạy cảm trước khi gửi.
- Giới hạn số email theo phút và theo giờ.
- Retry lỗi SMTP tạm thời bằng exponential backoff.
- Lưu processing log và delivery queue trong PostgreSQL.
- Cung cấp endpoint kiểm tra database, scheduler và cấu hình dependency.

## Kiến trúc tổng quát

```text
APScheduler
    │
    ▼
FindingProcessor
    │
    ├── DefectDojoClient ──HTTP GET──> DefectDojo API
    ├── Dedupe + Repository ─────────> PostgreSQL
    ├── Email Template + Redaction
    └── SMTP Client ─────────────────> SMTP Server
```

## Tổ chức source code

```text
Devsecops_auto_ticket/
│
├── src/                         # Chứa toàn bộ mã nguồn Python
│   ├── main.py                  # Khởi động FastAPI, database và scheduler
│   ├── config.py                # Đọc cấu hình từ biến môi trường và file .env
│   ├── scheduler.py             # Chạy tác vụ lấy findings theo chu kỳ
│   ├── processor.py             # Điều phối dedupe, tạo email và gửi email
│   ├── defectdojo_client.py     # Gọi Products API và Findings API của DefectDojo
│   ├── email_template.py        # Tạo tiêu đề, nội dung text và HTML của email
│   ├── redaction.py             # Che token, mật khẩu và dữ liệu nhạy cảm
│   ├── smtp_client.py           # Kết nối SMTP, gửi email và phân loại lỗi retry
│   ├── database.py              # Quản lý SQLAlchemy engine và database session
│   ├── db_models.py             # Khai báo bảng và trạng thái trong database
│   ├── repositories.py          # Đọc/ghi processing log và delivery queue
│   ├── schemas.py               # Khai báo cấu trúc dữ liệu bằng Pydantic
│   └── health.py                # Cung cấp các API health check
│
├── config/                      # Chứa cấu hình nghiệp vụ
│   ├── project_mapping.example.json # Bản mapping mẫu có thể commit
│   └── project_mapping.local.json   # Mapping thực tế; bị Git/Docker ignore
├── .env                         # Cấu hình thực tế; không được commit lên Git
├── .env.example                 # Mẫu biến môi trường
├── requirements.txt             # Python dependencies được pin version
├── Dockerfile                   # Build container cho ứng dụng
├── docker-compose.yml           # Chạy ứng dụng và PostgreSQL
├── .dockerignore                # Loại file khỏi Docker build context
└── .gitignore                   # Loại secret, cache và file local khỏi Git
```

## Luồng xử lý

### Chống trùng theo finding ID

Chống trùng dùng trực tiếp `finding_id`; giữ unique theo finding và cặp
`(finding_id, recipient_email)`. Không còn module `dedupe.py` hoặc cột
`dedupe_key` trong hai model. Các file migration đã được bỏ theo yêu cầu.
Database hiện hữu cần được chỉnh schema riêng trước khi chạy code mới;
`create_all()` và TRUNCATE không xóa các cột cũ. Không có thay đổi database
thật được thực hiện trong bước chỉnh source này.

### Remediation SLA KPI

Chính sách duy nhất ở `src/sla.py` (`SLA_BY_SEVERITY`): Critical 4 hours,
High 24 hours, Medium 7 days, Low 30 days. Info/Informational và severity không
nhận diện dùng Best effort, không có due date. Deadline hiển thị
`YYYY-MM-DD HH:MM` theo `Asia/Ho_Chi_Minh` trong text và HTML.
Để thay KPI, chỉ sửa bảng này và test SLA tương ứng; schema/template không tự
tính thời lượng. Runtime vẫn tính từ lúc processor xử lý finding, không từ
timestamp tạo DefectDojo (chưa có timestamp đó trong mapping hiện tại).
Email đã lưu queue không được tự tính lại deadline. Các mẫu Word/JSON và
preview trước đây là dữ liệu lịch sử, không phải chính sách SLA đang chạy.

```text
1. FastAPI khởi động và kiểm tra/khởi tạo các bảng database.
2. APScheduler đăng ký một interval job và chạy cycle đầu tiên ngay lập tức.
3. Processor xử lý các email đang chờ hoặc đến hạn retry.
4. Ứng dụng tìm product ID qua DefectDojo Products API.
5. Ứng dụng lấy active + verified findings theo product và phân trang.
6. Mỗi finding được chuẩn hóa thành DefectDojoFinding.
7. Processor kiểm tra trạng thái cũ và dedupe key trong PostgreSQL.
8. Finding mới được ánh xạ đến người nhận theo file mapping local đã cấu hình.
9. Nội dung email được tạo, escape HTML và che dữ liệu nhạy cảm.
10. Mỗi người nhận có một delivery độc lập trong database.
11. Queue kiểm tra SMTP quota rồi gửi các delivery đến hạn.
12. Kết quả được cập nhật thành SENT, RETRY_PENDING hoặc FAILED.
```

## Yêu cầu hệ thống

### Chạy bằng Docker

- Docker Engine hoặc Docker Desktop.
- Docker Compose v2.
- Kết nối được đến DefectDojo API và SMTP server.

### Chạy trực tiếp

- Python 3.13.
- PostgreSQL 16 hoặc phiên bản tương thích.
- Kết nối được đến DefectDojo API và SMTP server.

## Khởi chạy nhanh bằng Docker Compose

### 1. Tạo file cấu hình

```bash
cp .env.example .env
cp config/project_mapping.example.json config/project_mapping.local.json
```

Cập nhật `.env` với URL/token DefectDojo, thông tin SMTP và database password thực tế. Không commit file này lên Git. Các biến `POSTGRES_*` và credential trong `DATABASE_URL` phải khớp nhau.

### 2. Cấu hình project mapping

Cập nhật `config/project_mapping.local.json`. File này bị Git và Docker build context bỏ qua; chỉ commit `config/project_mapping.example.json`. Ví dụ:

```json
{
  "projects": [
    {
      "product_name": "payment-api",
      "to_destinations": ["payment-team@example.com"],
      "cc_destinations": ["security@example.com"]
    }
  ]
}
```

`product_name` phải khớp tên Product trong DefectDojo. Mapping cũ dạng
`defectdojo-product:display-name` vẫn được đọc; alias được dùng trong subject.
Có thể khai báo `display_name` riêng, ưu tiên hơn alias. Nếu không có alias,
subject dùng tên product từ DefectDojo:
`[DEVSECOPS] [High] [product] - FindingID: 3679 - Finding title`.
Có thể đổi prefix bằng `subject_prefix` trong mapping.

Email rút gọn theo 5 scanner; xem `EMAIL_TEMPLATE_PREVIEWS.md` với 12 mẫu từ
tài liệu. SonarQube lấy message/rule/location thay vì flows; Gitleaks không đưa
Secret/Match vào description; Dependency-Check lấy filepath và Impact ghi rõ;
Trivy lấy target/fixed version; ZAP giữ mô tả và mitigation có giới hạn.
Không hiện CWE-0, fingerprint, Impact/Action trống hoặc footer boilerplate.
Description giới hạn 600 ký tự, Impact/Action 450 ký tự trước dấu báo rút gọn.
Plain text căn nhãn 20 ký tự; HTML dùng các cột có chiều rộng thống nhất.
Queue hiện vẫn chỉ lưu plain text. Email client dùng font tỷ lệ có thể hiển thị
khoảng trắng không đều dù dấu hai chấm ở cùng vị trí ký tự.

### 3. Build và chạy

```bash
docker compose up --build -d
```

### 4. Kiểm tra trạng thái

```bash
docker compose ps
curl http://localhost:8000/health
curl http://localhost:8000/health/db
curl http://localhost:8000/health/dependencies
```

### 5. Xem log

```bash
docker compose logs -f app
```

### 6. Dừng ứng dụng

```bash
docker compose down
```

Để xóa cả PostgreSQL volume và toàn bộ dữ liệu:

```bash
docker compose down -v
```

> Lệnh `down -v` xóa dữ liệu database và không thể hoàn tác nếu chưa có backup.

## Chạy trực tiếp trên macOS/Linux

### 1. Tạo virtual environment

```bash
python3.13 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```


### 2. Chuẩn bị PostgreSQL và `.env`

Tạo `.env` từ file mẫu. Khi chạy ứng dụng ngoài Docker, đổi hostname database từ `postgres` thành `localhost` hoặc hostname PostgreSQL thực tế:

```dotenv
DATABASE_URL=postgresql+psycopg://app_user:<password>@localhost:5432/auto_ticket
```

### 3. Khởi chạy ứng dụng

```bash
uvicorn main:app --app-dir src --host 0.0.0.0 --port 8000 --no-access-log
```

Mở `http://localhost:8000/health` để kiểm tra.

## Biến môi trường

| Biến | Bắt buộc | Mặc định | Mô tả |
|---|---:|---:|---|
| `DEFECTDOJO_BASE_URL` | Có | — | Base URL của DefectDojo |
| `DEFECTDOJO_API_TOKEN` | Có | — | API token dùng header `Authorization: Token ...` |
| `DEFECTDOJO_FINDINGS_LIMIT` | Không | `100` | Số finding tối đa trên một trang API |
| `DEFECTDOJO_REQUEST_TIMEOUT_SECONDS` | Không | `60` | Timeout cho request DefectDojo |
| `POSTGRES_DB` | Docker Compose | `auto_ticket` | Tên database PostgreSQL |
| `POSTGRES_USER` | Docker Compose | `app_user` | User PostgreSQL |
| `POSTGRES_PASSWORD` | Docker Compose | — | Password PostgreSQL, bắt buộc khi chạy Compose |
| `DATABASE_URL` | Có | — | SQLAlchemy PostgreSQL connection URL; phải khớp các biến `POSTGRES_*` |
| `PROJECT_EMAIL_MAPPING_FILE` | Có điều kiện | — | Đường dẫn đến file mapping JSON |
| `PROJECT_EMAIL_MAPPING_JSON` | Có điều kiện | — | Mapping JSON inline; ghi đè entry cùng tên từ file |
| `SCHEDULER_INTERVAL_SECONDS` | Không | `300` | Khoảng cách giữa hai processing cycle |
| `NOTIFICATION_LEASE_TTL_SECONDS` | Không | `1800` | Thời gian lease dự kiến cho delivery |
| `SMTP_HOST` | Có | — | SMTP hostname |
| `SMTP_PORT` | Không | `587` | SMTP submission port |
| `SMTP_USERNAME` | Không | — | SMTP username |
| `SMTP_PASSWORD` | Không | — | SMTP password |
| `SMTP_FROM_EMAIL` | Có | — | Địa chỉ người gửi |
| `SMTP_USE_TLS` | Không | `true` | Bật STARTTLS |
| `SMTP_TIMEOUT_SECONDS` | Không | `30` | Timeout kết nối SMTP |
| `SMTP_MAX_EMAILS_PER_MINUTE` | Không | `30` | Quota email trong một phút |
| `SMTP_MAX_EMAILS_PER_HOUR` | Không | `500` | Quota email trong một giờ |
| `SMTP_MAX_ATTEMPTS` | Không | `3` | Tổng số lần thử gửi |
| `SMTP_RETRY_DELAY_SECONDS` | Không | `60` | Retry delay cơ sở |
| `SMTP_RETRY_BACKOFF_MULTIPLIER` | Không | `2` | Hệ số exponential backoff |

Phải cấu hình ít nhất một trong hai biến `PROJECT_EMAIL_MAPPING_FILE` hoặc `PROJECT_EMAIL_MAPPING_JSON`.

## DefectDojo API

Ứng dụng thực hiện các request chính sau:

```http
GET /api/v2/products/?name=<product_name>&limit=25
GET /api/v2/findings/?active=true&verified=true&limit=<limit>&offset=<offset>&test__engagement__product=<product_id>
```

Nếu response finding không chứa trực tiếp product name, client có thể gọi thêm các endpoint Test, Engagement và Product để hoàn thiện dữ liệu.


## Cơ chế chống duplicate

Ứng dụng chống gửi trùng ở ba lớp:

1. **Trong một lần fetch:** `seen_finding_ids` loại các finding có cùng ID khỏi danh sách trả về.
2. **Processing log:** bảng `processing_logs` chỉ có một bản ghi cho mỗi `finding_id`; finding đã `SENT` sẽ không được gửi lại.
3. **Delivery queue:** bảng `notification_deliveries` chỉ có một bản ghi cho mỗi cặp `(finding_id, recipient_email)`.

Cơ chế này chống gửi lại cùng một DefectDojo finding ID. Nếu cùng một lỗ hổng được tạo lại với ID mới, ứng dụng sẽ xem đó là finding mới.

## Database

Ứng dụng dùng SQLAlchemy và PostgreSQL. Khi startup, `Base.metadata.create_all()` tạo các bảng còn thiếu; dự án hiện chưa sử dụng migration tool.

### `processing_logs`

Lưu trạng thái tổng thể của mỗi finding:

- `PENDING`: đã ghi nhận và đang chờ xử lý.
- `SENT`: đã gửi email thành công.
- `FAILED`: xử lý hoặc gửi email thất bại.
- `SKIPPED`: bỏ qua do duplicate.
- `RATE_LIMITED`: đang chờ retry hoặc quota SMTP.
- `INVALID_RECIPIENT`: không tìm thấy người nhận hợp lệ.

### `notification_deliveries`

Lưu một delivery độc lập cho mỗi người nhận:

- `PENDING`: đang chờ gửi.
- `SENT`: đã gửi thành công.
- `RETRY_PENDING`: lỗi tạm thời và đang chờ thử lại.
- `FAILED`: đã hết số lần retry.

Các timestamp được lưu dưới dạng timezone-aware UTC. Log ứng dụng hiển thị theo timezone `Asia/Ho_Chi_Minh`.

## Retry và SMTP rate limit

Ứng dụng đếm các delivery `SENT` trong cửa sổ một phút và một giờ. Khi đạt quota, queue tạm dừng và xử lý lại trong cycle sau.

Lỗi timeout, mất kết nối và SMTP 4xx được xem là lỗi tạm thời. Retry delay được tính theo công thức:

```text
delay = SMTP_RETRY_DELAY_SECONDS × SMTP_RETRY_BACKOFF_MULTIPLIER^(attempt - 1)
```

Ví dụ với delay cơ sở 60 giây và multiplier 2: `60s → 120s → 240s`.


## Health check

| Endpoint | Mục đích |
|---|---|
| `GET /health` | Kiểm tra database và scheduler |
| `GET /health/db` | Chỉ kiểm tra kết nối PostgreSQL |
| `GET /health/dependencies` | Kiểm tra database, scheduler và cấu hình DefectDojo/SMTP/mapping |

Health check không gọi thử DefectDojo hoặc gửi thử SMTP; trạng thái hai dependency này chỉ phản ánh cấu hình có đầy đủ hay không.

## Logging và quan sát

Log được ghi ra standard output để Docker thu thập. Context vận hành có thể chứa finding ID, delivery ID, product, severity, recipient, retry count và trạng thái; không upload log lên GitHub hoặc chia sẻ công khai. Token và password không được ghi vào log.

Ví dụ xem log gần nhất:

```bash
docker compose logs --tail=200 app
```

## Bảo mật

- Không commit `.env`, `config/*.local.json`, API token, SMTP password, private key hoặc credential.
- Chỉ lưu dữ liệu giả trong các file `*.example.*`.
- Sử dụng token DefectDojo có quyền tối thiểu cần thiết.
- Sử dụng TLS cho SMTP trong môi trường production.
- Thay password mặc định và không hard-code password trong Compose.
- Giới hạn quyền truy cập PostgreSQL và không public port database ra ngoài host.
- Kiểm tra nội dung finding trước khi mở rộng các rule redaction.
- Không ghi token hoặc toàn bộ request header vào log.

## Giới hạn hiện tại

- Dedupe chỉ dựa trên `finding_id`, chưa tạo fingerprint từ nội dung lỗ hổng.
- Job store của APScheduler nằm trong memory, không persist lịch chạy.
- Cơ chế acquire delivery chưa phải distributed lock hoàn chỉnh; nên chạy một app replica.
- DefectDojo HTTP client chưa có retry policy riêng.
- Cache Test/Engagement/Product chỉ tồn tại trong một processing cycle.
- Database schema được tạo bằng `create_all`; chưa có versioned migration.

## Khắc phục sự cố

### `/health` trả về HTTP 503

Kiểm tra container, database và scheduler:

```bash
docker compose ps
docker compose logs --tail=200 app
docker compose logs --tail=100 postgres
```

### Không lấy được findings

- Kiểm tra `DEFECTDOJO_BASE_URL` và `DEFECTDOJO_API_TOKEN`.
- Kiểm tra tên product trong mapping có khớp chính xác với DefectDojo.
- Đảm bảo finding có `active=true` và `verified=true`.
- Kiểm tra kết nối mạng và timeout đến DefectDojo.

### Không gửi được email

- Kiểm tra SMTP host, port, username và password.
- Kiểm tra `SMTP_USE_TLS` có phù hợp với server hay không.
- Kiểm tra quota theo phút/giờ và các delivery `RETRY_PENDING`.
- Kiểm tra firewall cho kết nối outbound đến SMTP server.

## Công nghệ sử dụng

- Python 3.13
- FastAPI và Uvicorn
- APScheduler
- Requests
- SQLAlchemy 2
- PostgreSQL và psycopg 3
- Pydantic 2 và pydantic-settings
- Docker và Docker Compose

## License

Dự án hiện chưa khai báo license. Thêm file `LICENSE` trước khi phân phối hoặc công khai source code.
