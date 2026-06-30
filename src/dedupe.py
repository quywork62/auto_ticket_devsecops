"""Generate duplicate-prevention keys for DefectDojo findings."""

from schemas import DefectDojoFinding


def build_dedupe_key(finding: DefectDojoFinding) -> str:
    """Use the DefectDojo finding ID as the duplicate-prevention key."""
    return str(finding.finding_id)
