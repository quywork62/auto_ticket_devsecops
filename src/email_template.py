"""Build safe plain-text and HTML notification email content."""

from dataclasses import dataclass
from html import escape
import re
from textwrap import fill

from redaction import MASK, redact_secrets
from schemas import DefectDojoFinding, SlaPolicy, TicketAction
from sla import format_due_at

MAX_EMAIL_SUBJECT_LENGTH = 200
EMAIL_SUBJECT_ELLIPSIS = "....."
DEFAULT_EMAIL_SUBJECT_PREFIX = "DEVSECOPS"
FIELD_LABEL_WIDTH = 20
SUPPORT_EMAIL = "devsecops@example.com"
MAX_DETAIL_LENGTH = 600
MAX_ACTION_LENGTH = 450


def _clean_import_text(value: str | None) -> str:
    """Convert import separators without removing masking asterisks."""
    return re.sub(r"\bNEWLINE\b", "\n", value or "").replace("\u2028", "\n").strip()


def _import_fields(value: str) -> dict[str, str]:
    pattern = re.compile(r"\*\*([^*\n]+?)\s*:\s*\*\*|\*\*([^*\n]+?)\*\*\s*:")
    matches = list(pattern.finditer(value))
    return {
        (match.group(1) or match.group(2)).strip().lower():
        value[match.end():matches[i+1].start() if i+1 < len(matches) else len(value)].strip()
        for i, match in enumerate(matches)
    }


def _excerpt(value: str | None, limit: int) -> str | None:
    if not value:
        return None
    text = redact_secrets(_clean_import_text(value))
    text = re.sub(r"(?<=-)\n(?=\w)", "", text)
    text = re.sub(r"(?<!\n)\n(?!\n)", " ", text)
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + "… [Full details in DefectDojo]"


def _presentation_finding(finding: DefectDojoFinding) -> DefectDojoFinding:
    """Summarize known import formats on a copy; never change source evidence."""
    description = _clean_import_text(finding.description)
    fields = _import_fields(description)
    scanner = (finding.scanner_type or "").lower()
    updates: dict[str, object] = {}
    if "sonarqube" in scanner and fields.get("message"):
        description = fields["message"]
        updates["rule_id"] = fields.get("rule") or finding.rule_id
        component = fields.get("componentkey path") or fields.get("component")
        if component:
            updates["file_path"] = component.split(":", 1)[-1]
        if finding.line is None:
            line = fields.get("line", "")
            if not line.isdigit():
                match = re.search(r"startLine:\s*(\d+)", fields.get("textrange", ""))
                line = match.group(1) if match else ""
            updates["line"] = int(line) if line.isdigit() else None
    elif "gitleaks" in scanner:
        updates["rule_id"] = fields.get("rule id") or finding.rule_id
        if fields.get("secret") or fields.get("match"):
            description = "Potential hardcoded credential detected. See the affected file and rule."
    elif "dependency" in scanner:
        if fields.get("filepath"):
            updates["file_path"] = fields["filepath"]
        description = description.split("**Source:", 1)[0].strip()
    elif "trivy" in scanner:
        updates["container_image"] = finding.container_image or fields.get("target")
        fixed_lines = (fields.get("fixed version") or "").splitlines()
        fixed = finding.fixed_version or (fixed_lines[0] if fixed_lines else None)
        updates["fixed_version"] = fixed
        if fields:
            description = description.split("**Target:", 1)[0].strip()
        if fixed and _clean_import_text(finding.mitigation) == fixed:
            updates["mitigation"] = f"Upgrade {finding.component_name or 'the affected package'} to {fixed}."
    impact = _clean_import_text(finding.impact)
    # Only use an explicit Impact section, not arbitrary scanner evidence.
    if not impact:
        match = re.search(r"(?ims)^##\s+Impact\s*\n(.*?)(?=^##\s|\Z)", description)
        if match:
            impact = match.group(1).strip()
            description = (description[:match.start()] + description[match.end():]).strip()
    if finding.cwe in (0, "0", "CWE-0"):
        updates["cwe"] = None
    updates["description"] = _excerpt(description, MAX_DETAIL_LENGTH)
    updates["impact"] = _excerpt(impact, MAX_ACTION_LENGTH)
    updates["mitigation"] = _excerpt(updates.get("mitigation", finding.mitigation), MAX_ACTION_LENGTH)
    updates["fingerprint"] = None
    return finding.model_copy(update=updates)


@dataclass(frozen=True)
class TicketContent:
    """Rendered notification content and audit metadata."""

    finding_id: int
    subject: str
    body: str
    html_body: str
    ticket_action: TicketAction
    priority: str
    sla_target: str
    sla_due_at: str


def build_subject(
    finding: DefectDojoFinding,
    *,
    subject_prefix: str | None = None,
    subject_product: str | None = None,
) -> str:
    """Build a redacted email subject capped at the configured length."""
    prefix = redact_secrets(
        _non_empty_text(subject_prefix) or DEFAULT_EMAIL_SUBJECT_PREFIX
    )
    title = _redact_contextual_text(finding, finding.title)
    product = redact_secrets(subject_product or finding.product or "Unmapped")
    subject = f"[{prefix}] [{redact_secrets(finding.severity)}] [{product}] - FindingID: {finding.finding_id} - {title}"
    subject = re.sub(r"[\r\n]+", " ", subject)
    return _truncate_text(subject, MAX_EMAIL_SUBJECT_LENGTH)


def build_ticket_content(
    finding: DefectDojoFinding,
    defectdojo_base_url: str | None = None,
    *,
    sla_policy: SlaPolicy | None = None,
    ticket_action: TicketAction = TicketAction.CREATE,
    subject_prefix: str | None = None,
    subject_product: str | None = None,
) -> TicketContent:
    """Render both text and HTML email content plus audit metadata."""
    priority = sla_policy.priority if sla_policy else "N/A"
    sla_target = sla_policy.target if sla_policy else "N/A"
    sla_due_at = format_due_at(sla_policy.due_at if sla_policy else None) or "N/A"
    return TicketContent(
        finding_id=finding.finding_id,
        subject=build_subject(
            finding,
            subject_prefix=subject_prefix,
            subject_product=subject_product,
        ),
        body=build_body(
            finding,
            defectdojo_base_url,
            sla_policy=sla_policy,
        ),
        html_body=build_html_body(
            finding,
            defectdojo_base_url,
            sla_policy=sla_policy,
        ),
        ticket_action=ticket_action,
        priority=priority,
        sla_target=sla_target,
        sla_due_at=sla_due_at,
    )


def build_body(
    finding: DefectDojoFinding,
    defectdojo_base_url: str | None = None,
    *,
    sla_policy: SlaPolicy | None = None,
) -> str:
    """Render the plain-text finding notification body."""
    finding = _presentation_finding(finding)
    sections = [
        _format_text_section("Security Finding", _build_summary_fields(finding)),
        _format_text_section("Finding Details", _build_description_fields(finding)),
        _format_text_section("Affected Location", _build_location_fields(finding)),
        _format_text_section("Technical Details", _build_technical_fields(finding)),
        _format_text_section("Security Impact", text=_impact_text(finding)),
        _format_text_section("Recommended Action", text=_mitigation_text(finding)),
        _format_text_section(
            "Remediation Tracking",
            _build_tracking_fields(finding, defectdojo_base_url, sla_policy),
        ),
    ]
    sections.append(_format_text_section(
        "Technical Support",
        text=f"For assistance with this finding, contact:\n{SUPPORT_EMAIL}",
    ))
    return "\n\n".join(section for section in sections if section) + "\n"


def build_html_body(
    finding: DefectDojoFinding,
    defectdojo_base_url: str | None = None,
    *,
    sla_policy: SlaPolicy | None = None,
) -> str:
    """Render an escaped HTML alternative with clickable links."""
    finding = _presentation_finding(finding)
    sections = [
        _format_html_section("Security Finding", _build_summary_fields(finding)),
        _format_html_section("Finding Details", _build_description_fields(finding)),
        _format_html_section("Affected Location", _build_location_fields(finding)),
        _format_html_section("Technical Details", _build_technical_fields(finding)),
        _format_html_section("Security Impact", text=_impact_text(finding)),
        _format_html_section("Recommended Action", text=_mitigation_text(finding)),
        _format_html_section(
            "Remediation Tracking",
            _build_tracking_fields(finding, defectdojo_base_url, sla_policy),
            link_label="View in DefectDojo",
        ),
    ]
    sections.append(
        '<h3>Technical Support</h3><p>For assistance with this finding, contact:<br>'
        f'<a href="mailto:{SUPPORT_EMAIL}">{SUPPORT_EMAIL}</a></p>'
    )
    html_sections = "\n    ".join(section for section in sections if section)

    return f"""<!doctype html>
<html>
  <body>
    {html_sections}
  </body>
</html>
"""


def _build_finding_url(defectdojo_base_url: str | None, finding_id: int) -> str | None:
    """Build a direct DefectDojo finding URL when a base URL is available."""
    if not defectdojo_base_url:
        return None
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


def _build_summary_fields(finding: DefectDojoFinding) -> list[tuple[str, str]]:
    """Build identity fields without inventing missing scanner metadata."""
    scanner = (finding.scanner_type or "").replace(" (Generic Findings Import)", "") or None
    category = finding.category or (
        "Secret Management" if scanner and "gitleaks" in scanner.lower() else None
    )
    status_parts = []
    if finding.active is not None:
        status_parts.append("Active" if finding.active else "Inactive")
    if finding.verified is not None:
        status_parts.append("Verified" if finding.verified else "Unverified")
    return _compact_fields(
        [
            ("Project", finding.product),
            ("Scanner", scanner),
            ("Category", category),
            ("Finding ID", finding.finding_id),
            ("Severity", finding.severity),
            ("Status", " / ".join(status_parts)),
        ]
    )


def _build_description_fields(finding: DefectDojoFinding) -> list[tuple[str, str]]:
    """Keep the DefectDojo description distinct from security impact."""
    return _compact_fields(
        [
            ("Title", _redact_contextual_text(finding, finding.title)),
            ("Description", _redact_contextual_text(finding, finding.description)),
        ]
    )


def _build_location_fields(finding: DefectDojoFinding) -> list[tuple[str, str]]:
    """Include only available source, endpoint, or cloud location fields."""
    cloud_fields = (
        _extract_cloud_fields(finding) if _looks_like_cloud_finding(finding) else {}
    )
    return _compact_fields(
        [
            ("Repository", finding.repository),
            ("File", finding.file_path),
            ("Line", finding.line),
            ("Endpoint", finding.endpoint),
            ("HTTP Method", finding.http_method),
            ("Parameter", finding.parameter),
            ("Container Image", finding.container_image),
            ("Resource", cloud_fields.get("resource")),
            ("Resource Type", cloud_fields.get("resource_type")),
            ("AWS Account", cloud_fields.get("aws_account")),
            ("Region", cloud_fields.get("region")),
        ]
    )


def _build_technical_fields(finding: DefectDojoFinding) -> list[tuple[str, str]]:
    """Render scanner evidence and scores when DefectDojo supplies them."""
    cloud_fields = (
        _extract_cloud_fields(finding) if _looks_like_cloud_finding(finding) else {}
    )
    cwe = str(finding.cwe) if _has_value(finding.cwe) else None
    if cwe and not cwe.upper().startswith("CWE-"):
        cwe = f"CWE-{cwe}"
    return _compact_fields(
        [
            ("CWE", cwe),
            ("Vulnerability", finding.vuln_id_from_tool or finding.cve),
            ("CVSS", finding.cvss_score),
            ("EPSS", finding.epss_score),
            ("Rule", finding.rule_id),
            ("Secret Type", finding.secret_type),
            ("Fingerprint", finding.fingerprint),
            ("Component / Package", finding.component_name),
            ("Installed Version", finding.component_version),
            ("Fixed Version", finding.fixed_version),
            ("Control ID", cloud_fields.get("control_id")),
            ("Standard", cloud_fields.get("standard")),
            ("Finding Reference", cloud_fields.get("finding_reference")),
            ("Compliance Status", cloud_fields.get("compliance_status")),
        ]
    )


def _build_tracking_fields(
    finding: DefectDojoFinding,
    defectdojo_base_url: str | None,
    sla_policy: SlaPolicy | None,
) -> list[tuple[str, str]]:
    """Return policy dates and the direct finding link when available."""
    due_at = format_due_at(sla_policy.due_at if sla_policy else None)
    return _compact_fields(
        [
            ("SLA", sla_policy.target if sla_policy else None),
            ("Due Date", due_at),
            ("View in DefectDojo", _build_finding_url(defectdojo_base_url, finding.finding_id)),
        ]
    )


def _impact_text(finding: DefectDojoFinding) -> str:
    if _has_value(finding.impact):
        return _redact_contextual_text(finding, finding.impact)
    return ""


def _mitigation_text(finding: DefectDojoFinding) -> str:
    if _has_value(finding.mitigation):
        return _redact_contextual_text(finding, finding.mitigation)
    return ""


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
        "resource_type": finding.resource_type,
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


def _format_text_section(
    heading: str,
    fields: list[tuple[str, str]] | None = None,
    *,
    text: str | None = None,
) -> str:
    """Format one populated section using the requested text layout."""
    if not fields and not text:
        return ""
    lines = [heading, "-" * len(heading)]
    if fields:
        width = FIELD_LABEL_WIDTH
        for label, value in fields:
            normalized = "\n".join(
                fill(part.strip(), width=88 - width - 3, break_long_words=False,
                     break_on_hyphens=False)
                for part in value.splitlines() if part.strip()
            )
            indented = normalized.replace("\n", "\n" + " " * (width + 3))
            lines.append(f"{label:<{width}} : {indented}")
    if text:
        lines.append(_format_paragraph(text))
    return "\n".join(lines)


def _format_html_section(
    heading: str,
    fields: list[tuple[str, str]] | None = None,
    *,
    text: str | None = None,
    link_label: str | None = None,
) -> str:
    """Format one populated HTML section with escaped field values."""
    if not fields and not text:
        return ""
    parts = [f"<h3>{escape(heading)}</h3>"]
    if fields:
        rows = []
        for label, value in fields:
            display_value = (
                _format_html_link(value, value)
                if label == link_label
                else escape(value).replace("\n", "<br>")
            )
            rows.append(
                f'<tr><th scope="row" width="180" align="left" valign="top" '
                f'style="width:180px;padding:3px 8px 3px 0;font-weight:normal">{escape(label)}</th>'
                f'<td width="12" valign="top" style="width:12px;padding:3px 0">:</td>'
                f'<td valign="top" style="padding:3px 0;word-break:break-word">{display_value}</td></tr>'
            )
        parts.append('<table cellpadding="0" cellspacing="0" border="0" width="100%" '
                     'style="width:100%;border-collapse:collapse;table-layout:fixed">\n'
                     + "\n".join(rows) + "\n</table>")
    if text:
        parts.append(_format_html_paragraph(text))
    return "\n".join(parts)


def _format_paragraph(value: str) -> str:
    """Normalize Markdown-like text into wrapped plain-text paragraphs."""
    if value == "N/A":
        return value
    paragraphs = [
        part.strip()
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
        part.strip()
        for part in value.splitlines()
        if part.strip()
    ]
    if not paragraphs:
        return "<p>N/A</p>"
    return "\n".join(f"<p>{escape(paragraph)}</p>" for paragraph in paragraphs)


def _format_html_link(url: str, label: str) -> str:
    """Return an escaped clickable link."""
    escaped_url = escape(url, quote=True)
    return f'<a href="{escaped_url}">{escape(label)}</a>'
