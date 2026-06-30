"""Build safe plain-text and HTML notification email content."""

from dataclasses import dataclass
from datetime import datetime, timezone
from html import escape
import re
from textwrap import fill

from redaction import MASK, redact_secrets
from schemas import DefectDojoFinding, SlaPolicy, TicketAction

MAX_EMAIL_SUBJECT_LENGTH = 200
EMAIL_SUBJECT_ELLIPSIS = "....."
DEFAULT_EMAIL_SUBJECT_PREFIX = "VJA-DEVSECOPS"
SUPPORT_TEAM_NAME = "DevSecOps Team"


@dataclass(frozen=True)
class TicketContent:
    """Rendered notification content and audit metadata."""

    finding_id: int
    subject: str
    body: str
    html_body: str
    ticket_action: TicketAction
    dedupe_key: str | None
    priority: str
    sla_target: str
    sla_due_at: str


def build_subject(
    finding: DefectDojoFinding,
    *,
    subject_prefix: str | None = None,
    subject_product_name: str | None = None,
) -> str:
    """Build a redacted email subject capped at the configured length."""
    prefix = redact_secrets(
        _non_empty_text(subject_prefix) or DEFAULT_EMAIL_SUBJECT_PREFIX
    )
    project_name = redact_secrets(
        _non_empty_text(subject_product_name)
        or _non_empty_text(finding.product)
        or "Unknown Project"
    )
    title = _redact_contextual_text(finding, finding.title)
    subject = (
        f"[{prefix}] [{finding.severity}] [{project_name}] - "
        f"FindingID: {finding.finding_id} - {title}"
    )
    return _truncate_text(subject, MAX_EMAIL_SUBJECT_LENGTH)


def build_ticket_content(
    finding: DefectDojoFinding,
    defectdojo_base_url: str | None = None,
    *,
    dedupe_key: str | None = None,
    sla_policy: SlaPolicy | None = None,
    ticket_action: TicketAction = TicketAction.CREATE,
    subject_prefix: str | None = None,
    subject_product_name: str | None = None,
    generated_at: datetime | None = None,
) -> TicketContent:
    """Render both text and HTML email content plus audit metadata."""
    generated_at = generated_at or datetime.now(timezone.utc)
    priority = sla_policy.priority if sla_policy else "N/A"
    sla_target = sla_policy.target if sla_policy else "N/A"
    sla_due_at = (
        sla_policy.due_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        if sla_policy and sla_policy.due_at
        else "N/A"
    )
    return TicketContent(
        finding_id=finding.finding_id,
        subject=build_subject(
            finding,
            subject_prefix=subject_prefix,
            subject_product_name=subject_product_name,
        ),
        body=build_body(
            finding,
            defectdojo_base_url,
            dedupe_key=dedupe_key,
            sla_policy=sla_policy,
            ticket_action=ticket_action,
            generated_at=generated_at,
        ),
        html_body=build_html_body(
            finding,
            defectdojo_base_url,
            dedupe_key=dedupe_key,
            sla_policy=sla_policy,
            ticket_action=ticket_action,
            generated_at=generated_at,
        ),
        ticket_action=ticket_action,
        dedupe_key=dedupe_key,
        priority=priority,
        sla_target=sla_target,
        sla_due_at=sla_due_at,
    )


def build_body(
    finding: DefectDojoFinding,
    defectdojo_base_url: str | None = None,
    *,
    dedupe_key: str | None = None,
    sla_policy: SlaPolicy | None = None,
    ticket_action: TicketAction = TicketAction.CREATE,
    generated_at: datetime | None = None,
) -> str:
    """Render the plain-text finding notification body."""
    generated_at = generated_at or datetime.now(timezone.utc)
    project_name = redact_secrets(finding.product or "N/A")
    impact = _redact_contextual_text(
        finding, finding.impact or finding.description or "N/A"
    )
    mitigation = _redact_contextual_text(finding, finding.mitigation or "N/A")
    finding_url = _build_finding_url(defectdojo_base_url, finding.finding_id)
    finding_details = _format_fields(_build_finding_detail_fields(finding))

    # Internal audit fields are intentionally not rendered in the email for now.
    # Uncomment this block and add it back to the return template when needed.
    # priority = sla_policy.priority if sla_policy else "N/A"
    # sla_target = sla_policy.target if sla_policy else "N/A"
    # sla_due_at = (
    #     sla_policy.due_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    #     if sla_policy and sla_policy.due_at
    #     else "N/A"
    # )
    # routing_fields = _format_fields(
    #     [
    #         ("Ticket Action", ticket_action.value),
    #         ("Priority", priority),
    #         ("SLA Target", sla_target),
    #         ("SLA Due At", sla_due_at),
    #         ("Dedupe Key", dedupe_key or "N/A"),
    #         ("Ticket Source", "DefectDojo Auto Ticket"),
    #     ]
    # )

    # Recommended Actions are intentionally not rendered in the email for now.
    # Uncomment this block and add it back to the return template when needed.
    # Recommended Actions
    # - Review the finding details in DefectDojo.
    # - Validate whether the finding affects the application or environment.
    # - Prioritize remediation based on severity, priority, and SLA target.
    # - Update the finding status in DefectDojo after remediation or acceptance.

    return f'''You are receiving this email because DefectDojo detected an active and verified security finding for project "{project_name}".

DefectDojo URL: {finding_url}

Finding Details
{finding_details}

Impact
{_format_paragraph(impact)}

Mitigation / Recommendation
{_format_paragraph(mitigation)}

For support, contact {SUPPORT_TEAM_NAME}.

Security Note
Any API key, token, secret key, or password in the original finding should be masked as XXXXXX before sending to ticketing.

--
Please do not reply directly to this email.
This message was generated automatically by VJA DevSecOps Automation Service.
'''


def build_html_body(
    finding: DefectDojoFinding,
    defectdojo_base_url: str | None = None,
    *,
    dedupe_key: str | None = None,
    sla_policy: SlaPolicy | None = None,
    ticket_action: TicketAction = TicketAction.CREATE,
    generated_at: datetime | None = None,
) -> str:
    """Render an escaped HTML alternative with clickable links."""
    generated_at = generated_at or datetime.now(timezone.utc)
    project_name = redact_secrets(finding.product or "N/A")
    impact = _redact_contextual_text(
        finding, finding.impact or finding.description or "N/A"
    )
    mitigation = _redact_contextual_text(finding, finding.mitigation or "N/A")
    finding_url = _build_finding_url(defectdojo_base_url, finding.finding_id)
    finding_details = _build_finding_detail_fields(finding)

    # Internal audit fields are intentionally not rendered in the email for now.
    # Uncomment this block and add it back to the HTML template when needed.
    # priority = sla_policy.priority if sla_policy else "N/A"
    # sla_target = sla_policy.target if sla_policy else "N/A"
    # sla_due_at = (
    #     sla_policy.due_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    #     if sla_policy and sla_policy.due_at
    #     else "N/A"
    # )
    # routing_fields = [
    #     ("Ticket Action", ticket_action.value),
    #     ("Priority", priority),
    #     ("SLA Target", sla_target),
    #     ("SLA Due At", sla_due_at),
    #     ("Dedupe Key", dedupe_key or "N/A"),
    #     ("Ticket Source", "DefectDojo Auto Ticket"),
    # ]

    # Recommended Actions are intentionally not rendered in the email for now.
    # Uncomment this block and add it back to the HTML template when needed.
    # <p>Recommended Actions</p>
    # <ul>
    #   <li>Review the finding details in DefectDojo.</li>
    #   <li>Validate whether the finding affects the application or environment.</li>
    #   <li>Prioritize remediation based on severity, priority, and SLA target.</li>
    #   <li>Update the finding status in DefectDojo after remediation or acceptance.</li>
    # </ul>

    return f"""<!doctype html>
<html>
  <body>
    <p>You are receiving this email because DefectDojo detected an active and verified security finding for project &quot;{escape(project_name)}&quot;.</p>
    <p>DefectDojo URL: {_format_html_link(finding_url, f"Open DefectDojo Finding {finding.finding_id}")}</p>

    <p>Finding Details</p>
    {_format_html_fields(finding_details)}

    <p>Impact</p>
    {_format_html_paragraph(impact)}

    <p>Mitigation / Recommendation</p>
    {_format_html_paragraph(mitigation)}
    <p>For support, contact {escape(SUPPORT_TEAM_NAME)}.</p>

    <p>Security Note</p>
    <p>Any API key, token, secret key, or password in the original finding should be masked as XXXXXX before sending to ticketing.</p>

    <p>Please do not reply directly to this email.<br>
    This message was generated automatically by VJA DevSecOps Automation Service.</p>
  </body>
</html>
"""


def _build_finding_url(defectdojo_base_url: str | None, finding_id: int) -> str:
    """Build a direct DefectDojo finding URL when a base URL is available."""
    if not defectdojo_base_url:
        return "N/A"
    return f"{defectdojo_base_url.rstrip('/')}/finding/{finding_id}"


def _truncate_text(value: str, max_length: int) -> str:
    """Truncate text and reserve space for the configured ellipsis."""
    if len(value) <= max_length:
        return value
    return value[: max_length - len(EMAIL_SUBJECT_ELLIPSIS)] + EMAIL_SUBJECT_ELLIPSIS


def _non_empty_text(value: str | None) -> str | None:
    """Normalize optional text config values used by subject mapping."""
    if value is None:
        return None
    stripped = value.strip()
    return stripped or None


def _format_component(finding: DefectDojoFinding) -> str:
    """Combine dependency component name and version for display."""
    if finding.component_name and finding.component_version:
        return f"{finding.component_name}:{finding.component_version}"
    return finding.component_name or finding.component_version or "N/A"


def _build_finding_detail_fields(finding: DefectDojoFinding) -> list[tuple[str, str]]:
    """Build non-empty detail fields for the detected template type."""
    template_name = _select_detail_template(finding)
    project_name = redact_secrets(finding.product or "N/A")
    base_fields = [
        ("Project", project_name),
        ("Severity", finding.severity),
    ]

    if template_name == "cloud":
        cloud_fields = _extract_cloud_fields(finding)
        detail_fields = [
            ("Control ID", cloud_fields.get("control_id")),
            ("Standard", cloud_fields.get("standard")),
            ("AWS Account", cloud_fields.get("aws_account")),
            ("Region", cloud_fields.get("region")),
            ("Finding Reference", cloud_fields.get("finding_reference")),
            ("Resource", cloud_fields.get("resource")),
            ("Resource Type", cloud_fields.get("resource_type")),
            ("Compliance Status", cloud_fields.get("compliance_status")),
        ]
    elif template_name == "dast":
        detail_fields = [
            ("Endpoint", finding.endpoint),
            ("Parameter", finding.parameter),
            ("CWE", finding.cwe),
            ("Rule ID", finding.rule_id),
        ]
    elif template_name == "sast":
        detail_fields = [
            ("File Path", finding.file_path),
            ("Line", finding.line),
            ("Rule ID", finding.rule_id),
            ("CWE", finding.cwe),
        ]
    else:
        detail_fields = [
            ("Component", _format_component(finding)),
            ("CWE", finding.cwe),
            ("CVE", finding.cve),
            ("File Path", finding.file_path),
        ]

    return _compact_fields(base_fields + detail_fields)


def _select_detail_template(finding: DefectDojoFinding) -> str:
    """Select cloud, DAST, dependency, or SAST field layout."""
    if _looks_like_cloud_finding(finding):
        return "cloud"
    if _has_value(finding.endpoint) or _has_value(finding.parameter):
        return "dast"
    if _has_value(finding.cve) or _has_value(_format_component(finding)):
        return "dependency"
    if (
        _has_value(finding.file_path)
        or _has_value(finding.rule_id)
        or _has_value(finding.line)
    ):
        return "sast"
    return "dependency"


def _looks_like_cloud_finding(finding: DefectDojoFinding) -> bool:
    """Detect cloud findings from scanner, text, component, and resource fields."""
    scanner = (finding.scanner_type or "").lower()
    cloud_text = " ".join(
        value
        for value in (
            finding.title,
            finding.description or "",
            finding.impact or "",
            finding.mitigation or "",
        )
        if value
    ).lower()
    component = (_format_component(finding) or "").lower()
    cloud_markers = (
        "aws security hub",
        "security hub",
        "guardduty",
        "aws config",
        "cloudwatch",
        "aws account",
        "resource:",
        "region:",
        "compliance",
    )
    return (
        any(marker in scanner for marker in cloud_markers)
        or any(marker in cloud_text for marker in cloud_markers)
        or component.startswith("aws")
        or _has_value(finding.resource)
        or _has_value(finding.aws_account_id)
        or _has_value(finding.region)
        or _has_value(finding.compliance_status)
    )


def _extract_cloud_fields(finding: DefectDojoFinding) -> dict[str, str | None]:
    """Extract investigation-safe Cloud and Security Hub details."""
    text = "\n".join(
        value
        for value in (finding.impact, finding.description, finding.mitigation)
        if value
    )
    component = _format_component(finding)
    raw_resource = finding.resource or _extract_labeled_value(
        text, ("Resource", "Resource ID", "Resource ARN")
    )
    raw_account = finding.aws_account_id or _extract_labeled_value(
        text, ("AWS Account", "Account ID", "Account")
    )
    raw_region = finding.region or _extract_labeled_value(text, ("Region", "AWS Region"))
    raw_control = finding.rule_id or _extract_labeled_value(
        text, ("Control ID", "Security Control ID", "Rule ID")
    )
    securityhub_arn = _extract_securityhub_finding_arn(raw_control or "") or (
        _extract_securityhub_finding_arn(text)
    )
    securityhub_fields = (
        _parse_securityhub_finding_arn(securityhub_arn) if securityhub_arn else {}
    )

    return {
        "resource": _redact_cloud_identifier(raw_resource),
        "resource_type": finding.resource_type
        or (component if _has_value(component) else None),
        "aws_account": MASK if _has_value(raw_account) else securityhub_fields.get("account"),
        "region": raw_region or securityhub_fields.get("region"),
        "control_id": securityhub_fields.get("control_id") or raw_control,
        "standard": securityhub_fields.get("standard"),
        "finding_reference": securityhub_fields.get("finding_reference"),
        "compliance_status": finding.compliance_status
        or _extract_labeled_value(text, ("Compliance Status", "Compliance", "Status")),
    }


def _extract_labeled_value(text: str, labels: tuple[str, ...]) -> str | None:
    """Find the first line matching one of the supplied field labels."""
    for label in labels:
        pattern = rf"(?im)^\s*(?:[-*]\s*)?{re.escape(label)}\s*:\s*(.+?)\s*$"
        match = re.search(pattern, text)
        if match:
            return match.group(1).strip()
    return None


def _extract_securityhub_finding_arn(value: str) -> str | None:
    """Extract a Security Hub finding ARN from arbitrary text."""
    match = re.search(
        r"\barn:aws[a-zA-Z-]*:securityhub:[^\s]+/finding/[^\s,;<>]+",
        value,
    )
    if not match:
        return None
    return match.group(0).strip().rstrip(".")


def _parse_securityhub_finding_arn(value: str) -> dict[str, str] | None:
    """Parse safe control metadata from a supported Security Hub ARN."""
    match = re.match(
        r"^arn:aws[a-zA-Z-]*:securityhub:"
        r"(?P<region>[^:]+):"
        r"(?P<account>\d{12}):"
        r"subscription/(?P<standard_path>.+?)/"
        r"(?P<control_id>[^/]+)/finding/"
        r"(?P<finding_reference>[^/\s]+)$",
        value.strip(),
    )
    if not match:
        return None

    return {
        "control_id": match.group("control_id"),
        "standard": _format_security_standard(match.group("standard_path")),
        "account": MASK,
        "region": match.group("region"),
        "finding_reference": _short_reference(match.group("finding_reference")),
    }


def _format_security_standard(value: str) -> str:
    """Convert a Security Hub standard path to a readable label."""
    parts = [part for part in value.split("/") if part]
    if not parts:
        return value

    name = " ".join(_format_standard_word(word) for word in parts[0].split("-"))
    version = ""
    if len(parts) >= 3 and parts[1] == "v":
        version = f" v{parts[2]}"
    elif len(parts) >= 2:
        version = " " + " ".join(parts[1:])
    return f"{name}{version}".strip()


def _format_standard_word(value: str) -> str:
    """Preserve known security acronyms while title-casing other words."""
    acronyms = {"aws": "AWS", "cis": "CIS", "nist": "NIST", "pci": "PCI"}
    return acronyms.get(value.lower(), value.capitalize())


def _short_reference(value: str) -> str:
    """Shorten long finding references while retaining both ends."""
    if len(value) <= 16:
        return value
    return f"{value[:8]}...{value[-4:]}"


def _redact_cloud_identifier(value: object) -> str | None:
    """Mask account IDs and summarize Security Hub ARNs in cloud values."""
    if not _has_value(value):
        return None
    text = _redact_securityhub_finding_arns(redact_secrets(str(value)))
    return re.sub(r"\b\d{12}\b", MASK, text)


def _redact_contextual_text(finding: DefectDojoFinding, value: object) -> str:
    """Apply cloud-aware redaction or generic credential masking."""
    if not _has_value(value):
        return "N/A"
    if _looks_like_cloud_finding(finding):
        return _redact_cloud_identifier(value) or "N/A"
    return redact_secrets(value)


def _redact_securityhub_finding_arns(value: str) -> str:
    """Replace full Security Hub ARNs with control and short-reference text."""
    pattern = re.compile(
        r"\barn:aws[a-zA-Z-]*:securityhub:[^\s]+/finding/[^\s,;<>]+"
    )

    def replace(match: re.Match[str]) -> str:
        """Render one matched ARN as safe operational metadata."""
        parsed = _parse_securityhub_finding_arn(match.group(0).strip().rstrip("."))
        if not parsed:
            return MASK
        return (
            f"Control ID: {parsed['control_id']}; "
            f"Finding Reference: {parsed['finding_reference']}"
        )

    return pattern.sub(replace, value)


def _compact_fields(fields: list[tuple[str, object]]) -> list[tuple[str, str]]:
    """Remove empty fields and redact remaining display values."""
    compacted: list[tuple[str, str]] = []
    for label, value in fields:
        if not _has_value(value):
            continue
        compacted.append((label, redact_secrets(str(value))))
    return compacted


def _has_value(value: object) -> bool:
    """Return whether a value contains meaningful display data."""
    if value is None:
        return False
    if isinstance(value, str):
        normalized = value.strip()
        return normalized not in {"", "N/A", "[]", "{}", "None", "null"}
    if isinstance(value, (list, dict, tuple, set)):
        return bool(value)
    return True


def _format_fields(fields: list[tuple[str, str]]) -> str:
    """Format key-value fields as a plain-text bullet list."""
    return "\n".join(f"- {label}: {value}" for label, value in fields)


def _format_html_fields(fields: list[tuple[str, str]]) -> str:
    """Format escaped key-value fields as an HTML list."""
    items = "\n".join(
        f"<li>{escape(label)}: {escape(str(value))}</li>"
        for label, value in fields
    )
    return f"<ul>\n{items}\n</ul>"


def _format_paragraph(value: str) -> str:
    """Normalize Markdown-like text into wrapped plain-text paragraphs."""
    if value == "N/A":
        return value
    paragraphs = [
        _strip_markdown_emphasis(part.strip())
        for part in value.splitlines()
        if part.strip()
    ]
    if not paragraphs:
        return "N/A"
    return "\n".join(fill(paragraph, width=88) for paragraph in paragraphs)


def _format_html_paragraph(value: str) -> str:
    """Normalize and escape text into separate HTML paragraphs."""
    if value == "N/A":
        return "<p>N/A</p>"
    paragraphs = [
        _strip_markdown_emphasis(part.strip())
        for part in value.splitlines()
        if part.strip()
    ]
    if not paragraphs:
        return "<p>N/A</p>"
    return "\n".join(f"<p>{escape(paragraph)}</p>" for paragraph in paragraphs)


def _strip_markdown_emphasis(value: str) -> str:
    """Remove bold emphasis markers unsupported by the target display."""
    return value.replace("**", "")


def _format_html_link(url: str, label: str) -> str:
    """Return an escaped clickable link or N/A when no URL exists."""
    if url == "N/A":
        return "N/A"
    escaped_url = escape(url, quote=True)
    return f'<a href="{escaped_url}">{escape(label)}</a>'
