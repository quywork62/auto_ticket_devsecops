import sys
import json
from pathlib import Path

from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import db_models  # noqa: F401
from config import Settings
from database import Base
from db_models import (
    NotificationDelivery,
    NotificationStatus,
    ProcessingLog,
    ProcessingStatus,
    SmtpSendEvent,
)
from processor import FindingProcessor
from schemas import (
    DefectDojoFinding,
    EmailPayload,
    ManageEngineRequestResult,
    ProjectEmailMapping,
    TicketAction,
)
from manageengine_mapper import policy_for_severity


def build_settings(**overrides):
    values = {
        "DEFECTDOJO_BASE_URL": "https://dojo.example.com",
        "DEFECTDOJO_API_TOKEN": "token",
        "DATABASE_URL": "sqlite:///:memory:",
        "SMTP_HOST": "localhost",
        "SMTP_FROM_EMAIL": "devsecops@example.com",
        "MANAGEENGINE_DELIVERY_MODE": "api",
        "MANAGEENGINE_DRY_RUN": True,
        "MANAGEENGINE_BASE_URL": "https://servicedesk.example.com",
        "PROJECT_EMAIL_MAPPING_FILE": "",
        "PROJECT_EMAIL_MAPPING_JSON": "",
        **overrides,
    }
    return Settings.model_validate(values)


def build_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


class FakeManageEngineClient:
    def __init__(self, status="DRY_RUN", request_id=None):
        self.created_payloads = []
        self.status = status
        self.request_id = request_id

    def create_request(self, payload):
        self.created_payloads.append(payload)
        return ManageEngineRequestResult(
            request_id=self.request_id,
            status=self.status,
            raw_response={"input_data": {"request": {"subject": payload.subject}}},
        )


def build_finding(finding_id: int) -> DefectDojoFinding:
    return DefectDojoFinding(
        finding_id=finding_id,
        title="SQL Injection",
        severity="Critical",
        product="Customer Portal",
        endpoint="app.example.com/login",
        parameter="username",
        description="SQL injection in login form",
        mitigation="Use parameterized queries",
        date="2026-06-12",
    )


def test_project_mapping_defines_ticket_and_notification_recipients():
    mapping = ProjectEmailMapping(
        product_name="Customer Portal",
        ticket_mailbox="appsec-ticket@example.com",
        to_destinations=["team@example.com"],
    )

    assert str(mapping.ticket_mailbox) == "appsec-ticket@example.com"
    assert [str(email) for email in mapping.to_destinations] == ["team@example.com"]


def test_process_finding_api_dry_run_remains_pending():
    db = build_session()
    processor = FindingProcessor(build_settings(), db)
    fake_manageengine = FakeManageEngineClient()
    processor.manageengine_client = fake_manageengine

    processor.process_finding(build_finding(100))

    record = db.scalar(select(ProcessingLog).where(ProcessingLog.finding_id == 100))
    assert record is not None
    assert record.status == ProcessingStatus.PENDING
    assert record.ticket_status == "DRY_RUN"
    assert record.processed_at is not None
    assert record.dedupe_key is not None
    assert record.priority == "P1/Critical"
    assert record.sla_target == "7 days"
    assert len(fake_manageengine.created_payloads) == 1


def test_process_finding_api_unknown_response_is_failed():
    db = build_session()
    processor = FindingProcessor(build_settings(), db)
    processor.manageengine_client = FakeManageEngineClient(
        status="UNKNOWN",
        request_id=None,
    )

    processor.process_finding(build_finding(101))

    record = db.scalar(select(ProcessingLog).where(ProcessingLog.finding_id == 101))
    assert record is not None
    assert record.status == ProcessingStatus.FAILED
    assert "not confirmed" in record.error_message


def test_processing_log_dedupe_key_identifies_sent_duplicate():
    db = build_session()
    processor = FindingProcessor(build_settings(), db)

    db.add(
        ProcessingLog(
            finding_id=100,
            dedupe_key="dd:claim",
            status=ProcessingStatus.SENT,
        )
    )
    db.commit()

    duplicate = processor.processing_logs.get_sent_or_queued_by_dedupe_key("dd:claim")

    assert duplicate is not None
    assert duplicate.finding_id == 100
    assert duplicate.status == ProcessingStatus.SENT


def test_process_finding_skips_duplicate_dedupe_key_after_ticket_created():
    db = build_session()
    processor = FindingProcessor(build_settings(), db)
    fake_manageengine = FakeManageEngineClient(status="success", request_id="1001")
    processor.manageengine_client = fake_manageengine

    processor.process_finding(build_finding(100))
    processor.process_finding(build_finding(200))

    first = db.scalar(select(ProcessingLog).where(ProcessingLog.finding_id == 100))
    duplicate = db.scalar(select(ProcessingLog).where(ProcessingLog.finding_id == 200))
    assert first is not None
    assert duplicate is not None
    assert first.status == ProcessingStatus.SENT
    assert duplicate.status == ProcessingStatus.SKIPPED
    assert duplicate.dedupe_key == first.dedupe_key
    assert "Duplicate issue skipped" in duplicate.error_message
    assert len(fake_manageengine.created_payloads) == 1


def test_email_payload_uses_project_mapping_routing_fields():
    mapping = {
        "projects": [
            {
                "product_name": "Customer Portal",
                "ticket_mailbox": "appsec-ticket@example.com",
                "cc_destinations": [
                    "customer-portal-team@example.com",
                    "appsec-ticket@example.com",
                ],
                "group": "Application Security",
                "category": "Security",
                "subcategory": "Web Vulnerability",
            }
        ]
    }
    db = build_session()
    processor = FindingProcessor(
        build_settings(
            MANAGEENGINE_DELIVERY_MODE="email_fetch",
            PROJECT_EMAIL_MAPPING_JSON=json.dumps(mapping),
        ),
        db,
    )
    finding = build_finding(100)

    project_mapping = processor._resolve_project_mapping(finding)
    recipient = processor._resolve_ticket_mailbox(finding, project_mapping)
    assert recipient is not None
    cc_recipients = processor._resolve_cc_recipients(project_mapping, recipient)
    payload = processor._build_email_payload(
        finding=finding,
        recipient=recipient,
        dedupe_key="dd:test",
        sla_policy=policy_for_severity(finding.severity),
        ticket_action=TicketAction.CREATE,
        project_mapping=project_mapping,
        cc_recipients=cc_recipients,
    )

    assert str(payload.recipient_email) == "appsec-ticket@example.com"
    assert [str(email) for email in payload.cc_emails] == [
        "customer-portal-team@example.com"
    ]
    assert "Ticket Routing Fields" not in payload.body
    assert "- Group: Application Security" not in payload.body
    assert "- Category: Security" not in payload.body
    assert "- Subcategory: Web Vulnerability" not in payload.body
    assert "Ticket Routing Fields" not in payload.html_body
    assert "<strong>" not in payload.html_body


class RecordingSmtpClient:
    def __init__(self):
        self.sent_payloads = []

    def send(self, payload):
        self.sent_payloads.append(payload)


class RecordingRateLimiter:
    def __init__(self):
        self.sent_events = []

    def quota_available(self):
        return True

    def record_send(
        self,
        *,
        finding_id,
        recipient_email,
        cc_emails=None,
        flow_type=None,
        delivery_mode=None,
    ):
        self.sent_events.append(
            {
                "finding_id": finding_id,
                "recipient_email": recipient_email,
                "cc_emails": cc_emails,
                "flow_type": flow_type,
                "delivery_mode": delivery_mode,
            }
        )


class RecordingProcessingLogs:
    def __init__(self):
        self.sent_payload = None

    def get_by_finding_id(self, finding_id):
        return None

    def mark_sent(self, **kwargs):
        self.sent_payload = kwargs


def test_send_with_retry_records_one_explicit_mail_flow():
    processor = object.__new__(FindingProcessor)
    processor.settings = build_settings(SMTP_MAX_ATTEMPTS=1)
    processor.smtp_client = RecordingSmtpClient()
    processor.rate_limiter = RecordingRateLimiter()
    processor.processing_logs = RecordingProcessingLogs()
    payload = EmailPayload(
        finding_id=3282,
        recipient_email="ticket@example.com",
        to_emails=["team@example.com"],
        cc_emails=["lead@example.com"],
        subject="Security finding",
        body="Finding body",
        dedupe_key="dd:example",
    )

    processor._send_with_retry(
        payload,
        flow_type="ticket_email",
    )

    assert len(processor.smtp_client.sent_payloads) == 1
    ticket_email = processor.smtp_client.sent_payloads[0]
    assert str(ticket_email.recipient_email) == "ticket@example.com"
    assert [str(email) for email in ticket_email.to_emails] == ["team@example.com"]
    assert [str(email) for email in ticket_email.cc_emails] == ["lead@example.com"]
    assert processor.processing_logs.sent_payload["recipient_email"] == "ticket@example.com"
    assert processor.rate_limiter.sent_events[0]["flow_type"] == "ticket_email"
    assert processor.rate_limiter.sent_events[0]["recipient_email"] == (
        "ticket@example.com"
    )
    assert processor.rate_limiter.sent_events[0]["cc_emails"] == "lead@example.com"


def test_email_fetch_sends_ticket_mail_and_one_notify_mail_per_recipient():
    mapping = {
        "projects": [
            {
                "product_name": "Customer Portal",
                "ticket_mailbox": "appsec-ticket@example.com",
                "to_destinations": [
                    "customer-portal-team@example.com",
                    "security-lead@example.com",
                ],
                "cc_destinations": ["devsecops@example.com"],
            }
        ]
    }
    db = build_session()
    processor = FindingProcessor(
        build_settings(
            MANAGEENGINE_DELIVERY_MODE="email_fetch",
            PROJECT_EMAIL_MAPPING_JSON=json.dumps(mapping),
        ),
        db,
    )
    processor.smtp_client = RecordingSmtpClient()

    processor.process_finding(build_finding(300))

    assert len(processor.smtp_client.sent_payloads) == 3
    ticket_payload = processor.smtp_client.sent_payloads[0]
    first_notify_payload = processor.smtp_client.sent_payloads[1]
    second_notify_payload = processor.smtp_client.sent_payloads[2]
    assert str(ticket_payload.recipient_email) == "appsec-ticket@example.com"
    assert ticket_payload.to_emails == []
    assert ticket_payload.cc_emails == []
    assert str(first_notify_payload.recipient_email) == "customer-portal-team@example.com"
    assert first_notify_payload.to_emails == []
    assert [str(email) for email in first_notify_payload.cc_emails] == [
        "devsecops@example.com"
    ]
    assert str(second_notify_payload.recipient_email) == "security-lead@example.com"
    assert second_notify_payload.to_emails == []
    assert [str(email) for email in second_notify_payload.cc_emails] == [
        "devsecops@example.com"
    ]

    record = db.scalar(select(ProcessingLog).where(ProcessingLog.finding_id == 300))
    assert record is not None
    assert record.status == ProcessingStatus.SENT
    assert record.recipient_email == "appsec-ticket@example.com"

    events = list(
        db.scalars(
            select(SmtpSendEvent).where(SmtpSendEvent.finding_id == 300).order_by(SmtpSendEvent.id)
        )
    )
    assert len(events) == 3
    assert events[0].recipient_email == "appsec-ticket@example.com"
    assert events[0].cc_emails is None
    assert events[0].flow_type == "ticket_email"
    assert events[1].recipient_email == "customer-portal-team@example.com"
    assert events[1].cc_emails == "devsecops@example.com"
    assert events[1].flow_type == "notify_email"
    assert events[2].recipient_email == "security-lead@example.com"
    assert events[2].cc_emails == "devsecops@example.com"
    assert events[2].flow_type == "notify_email"
    assert {event.delivery_mode for event in events} == {"email_fetch"}


def test_api_mode_creates_ticket_then_sends_one_notify_mail_per_recipient():
    mapping = {
        "projects": [
            {
                "product_name": "Customer Portal",
                "ticket_mailbox": "appsec-ticket@example.com",
                "to_destinations": [
                    "customer-portal-team@example.com",
                    "security-lead@example.com",
                ],
                "cc_destinations": ["devsecops@example.com"],
            }
        ]
    }
    db = build_session()
    processor = FindingProcessor(
        build_settings(
            MANAGEENGINE_DELIVERY_MODE="api",
            PROJECT_EMAIL_MAPPING_JSON=json.dumps(mapping),
        ),
        db,
    )
    fake_manageengine = FakeManageEngineClient(status="success", request_id="1002")
    processor.manageengine_client = fake_manageengine
    processor.smtp_client = RecordingSmtpClient()

    processor.process_finding(build_finding(301))

    assert len(fake_manageengine.created_payloads) == 1
    assert len(processor.smtp_client.sent_payloads) == 2
    first_payload = processor.smtp_client.sent_payloads[0]
    second_payload = processor.smtp_client.sent_payloads[1]
    assert str(first_payload.recipient_email) == "customer-portal-team@example.com"
    assert first_payload.to_emails == []
    assert [str(email) for email in first_payload.cc_emails] == [
        "devsecops@example.com"
    ]
    assert str(second_payload.recipient_email) == "security-lead@example.com"
    assert second_payload.to_emails == []
    assert [str(email) for email in second_payload.cc_emails] == [
        "devsecops@example.com"
    ]

    events = list(
        db.scalars(
            select(SmtpSendEvent).where(SmtpSendEvent.finding_id == 301).order_by(SmtpSendEvent.id)
        )
    )
    assert len(events) == 2
    assert events[0].recipient_email == "customer-portal-team@example.com"
    assert events[0].cc_emails == "devsecops@example.com"
    assert events[0].flow_type == "notify_email"
    assert events[0].delivery_mode == "api"
    assert events[1].recipient_email == "security-lead@example.com"
    assert events[1].cc_emails == "devsecops@example.com"
    assert events[1].flow_type == "notify_email"
    assert events[1].delivery_mode == "api"


def test_rate_limited_ticket_retry_sends_notifications_after_success():
    mapping = {
        "projects": [
            {
                "product_name": "Customer Portal",
                "ticket_mailbox": "appsec-ticket@example.com",
                "to_destinations": [
                    "customer-portal-team@example.com",
                    "security-lead@example.com",
                ],
                "cc_destinations": ["devsecops@example.com"],
            }
        ]
    }
    db = build_session()
    processor = FindingProcessor(
        build_settings(
            MANAGEENGINE_DELIVERY_MODE="email_fetch",
            PROJECT_EMAIL_MAPPING_JSON=json.dumps(mapping),
            SMTP_MAX_EMAILS_PER_MINUTE=0,
        ),
        db,
    )
    finding = build_finding(302)
    processor.smtp_client = RecordingSmtpClient()
    processor.process_finding(finding)

    queued = db.scalar(
        select(ProcessingLog).where(ProcessingLog.finding_id == finding.finding_id)
    )
    assert queued is not None
    assert queued.status == ProcessingStatus.RATE_LIMITED
    queued.next_attempt_at = None
    db.commit()
    processor.rate_limiter.max_per_minute = 30

    processor.process_rate_limited_queue()

    assert len(processor.smtp_client.sent_payloads) == 3
    assert str(processor.smtp_client.sent_payloads[0].recipient_email) == (
        "appsec-ticket@example.com"
    )
    assert str(processor.smtp_client.sent_payloads[1].recipient_email) == (
        "customer-portal-team@example.com"
    )
    assert str(processor.smtp_client.sent_payloads[2].recipient_email) == (
        "security-lead@example.com"
    )
    record = db.scalar(
        select(ProcessingLog).where(ProcessingLog.finding_id == finding.finding_id)
    )
    assert record is not None
    assert record.status == ProcessingStatus.SENT


class TransientFailingSmtpClient:
    def send(self, payload):
        raise TimeoutError("temporary SMTP timeout")


def test_notification_failure_is_persisted_for_later_retry():
    mapping = {
        "projects": [
            {
                "product_name": "Customer Portal",
                "to_destinations": ["security-team@example.com"],
            }
        ]
    }
    db = build_session()
    processor = FindingProcessor(
        build_settings(
            MANAGEENGINE_DELIVERY_MODE="api",
            PROJECT_EMAIL_MAPPING_JSON=json.dumps(mapping),
        ),
        db,
    )
    processor.manageengine_client = FakeManageEngineClient(
        status="success",
        request_id="2001",
    )
    processor.smtp_client = TransientFailingSmtpClient()

    processor.process_finding(build_finding(303))

    delivery = db.scalar(
        select(NotificationDelivery).where(
            NotificationDelivery.finding_id == 303
        )
    )
    assert delivery is not None
    assert delivery.status == NotificationStatus.RETRY_PENDING
    assert delivery.retry_count == 1
    assert delivery.next_attempt_at is not None
    assert "temporary SMTP timeout" in delivery.error_message
