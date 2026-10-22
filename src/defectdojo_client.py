"""Fetch and normalize active, verified findings from the DefectDojo API."""

import logging
from urllib.parse import urljoin, urlsplit, parse_qs

import requests

from config import Settings
from schemas import DefectDojoFinding

logger = logging.getLogger(__name__)


class DefectDojoClient:
    """HTTP client with pagination and product-resolution caches."""

    def __init__(self, settings: Settings):
        """Store settings and initialize relationship lookup caches."""
        self.settings = settings
        self._test_cache: dict[int, dict] = {}
        self._engagement_cache: dict[int, dict] = {}
        self._product_cache: dict[int, dict] = {}
        self._test_type_cache: dict[int, dict] = {}

    def fetch_active_verified_findings(
        self, product_names: list[str] | None = None
    ) -> list[DefectDojoFinding]:
        """Fetch active and verified findings for configured product names only."""
        normalized_products = self._normalize_product_names(product_names)
        if not normalized_products:
            logger.warning("No DefectDojo product filters configured; skipping fetch")
            return []

        findings: list[DefectDojoFinding] = []
        seen_finding_ids: set[int] = set()

        for product_name in normalized_products:
            product_id = self._find_product_id_by_name(product_name)
            if product_id is None:
                logger.warning(
                    "Configured DefectDojo product not found; skipping product",
                    extra={"product": product_name},
                )
                continue

            for finding in self._fetch_active_verified_findings_for_product(product_id):
                if finding.finding_id in seen_finding_ids:
                    continue
                seen_finding_ids.add(finding.finding_id)
                findings.append(finding)

        logger.debug(
            "DefectDojo findings fetched",
            extra={"finding_count": len(findings)},
        )
        return findings

    def _fetch_active_verified_findings_for_product(
        self, product_id: int
    ) -> list[DefectDojoFinding]:
        """Fetch active and verified finding pages for one DefectDojo product."""
        findings: list[DefectDojoFinding] = []
        limit = self.settings.defectdojo_findings_limit
        offset = 0
        next_url: str | None = self._findings_url()
        visited: set[tuple[str, int]] = set()

        while next_url:
            next_url = self._safe_page_url(next_url)
            page_offset = int(parse_qs(urlsplit(next_url).query).get("offset", [offset])[0])
            page_key = (next_url, page_offset)
            if page_key in visited:
                raise ValueError("DefectDojo pagination repeated a page")
            visited.add(page_key)
            offset = page_offset
            logger.debug("DefectDojo findings page request started")
            response = requests.get(
                next_url,
                headers=self._headers(),
                params=(
                    {
                        "active": "true",
                        "verified": "true",
                        "limit": limit,
                        "offset": offset,
                        "test__engagement__product": product_id,
                    }
                    if "?" not in next_url
                    else None
                ),
                timeout=self.settings.defectdojo_request_timeout_seconds,
                allow_redirects=False,
            )
            if 300 <= response.status_code < 400:
                raise ValueError("DefectDojo API redirects are not allowed")
            response.raise_for_status()
            payload = response.json()

            for raw_finding in payload.get("results", []):
                finding = self._map_finding(raw_finding)
                findings.append(finding)

            next_url = payload.get("next")
            if next_url:
                continue

            count = payload.get("count")
            offset += limit
            if count is not None and offset < int(count):
                next_url = self._findings_url()
            else:
                next_url = None

        return findings

    def _safe_page_url(self, value: str) -> str:
        """Never forward the API token to another origin or resource."""
        url = urljoin(self._findings_url(), value)
        expected, actual = urlsplit(self._findings_url()), urlsplit(url)
        if (actual.scheme, actual.hostname, actual.port, actual.path) != (
            expected.scheme, expected.hostname, expected.port, expected.path
        ) or actual.username or actual.password or actual.fragment:
            raise ValueError("Unsafe DefectDojo pagination URL")
        return url

    def _headers(self) -> dict[str, str]:
        """Build DefectDojo token-authentication headers."""
        return {
            "Authorization": f"Token {self.settings.defectdojo_api_token}",
            "Accept": "application/json",
        }

    def _findings_url(self) -> str:
        """Return the canonical findings endpoint."""
        return urljoin(self.settings.defectdojo_base_url + "/", "api/v2/findings/")

    def _api_url(self, path: str) -> str:
        """Join an API-relative path to the configured DefectDojo base URL."""
        return urljoin(self.settings.defectdojo_base_url + "/", path.lstrip("/"))

    def _products_url(self) -> str:
        """Return the canonical products endpoint."""
        return urljoin(self.settings.defectdojo_base_url + "/", "api/v2/products/")

    def _normalize_product_names(self, product_names: list[str] | None) -> list[str]:
        """Return unique non-empty product names preserving input order."""
        normalized: list[str] = []
        seen: set[str] = set()
        for product_name in product_names or []:
            clean_name = product_name.strip()
            normalized_name = clean_name.lower()
            if not clean_name or normalized_name in seen:
                continue
            seen.add(normalized_name)
            normalized.append(clean_name)
        return normalized

    def _find_product_id_by_name(self, product_name: str) -> int | None:
        """Resolve a DefectDojo product ID by exact product name."""
        response = requests.get(
            self._products_url(),
            headers=self._headers(),
            params={"name": product_name, "limit": 25},
            timeout=self.settings.defectdojo_request_timeout_seconds,
        )
        response.raise_for_status()
        payload = response.json()
        for product in payload.get("results", []):
            if str(product.get("name", "")).strip().lower() == product_name.lower():
                product_id = product.get("id")
                if isinstance(product_id, int):
                    return product_id
        return None

    def _get_json(self, path: str) -> dict:
        """GET one DefectDojo resource and return its decoded JSON object."""
        response = requests.get(
            self._api_url(path),
            headers=self._headers(),
            timeout=self.settings.defectdojo_request_timeout_seconds,
        )
        response.raise_for_status()
        return response.json()

    def _map_finding(self, raw: dict) -> DefectDojoFinding:
        """Convert one raw DefectDojo result into the internal finding schema."""
        endpoints = self._extract_endpoint_values(raw.get("endpoints") or [])

        product_name = self._resolve_product_name(raw)
        return DefectDojoFinding(
            finding_id=raw["id"],
            title=raw.get("title") or "Untitled finding",
            severity=raw.get("severity") or "Unknown",
            description=raw.get("description"),
            impact=raw.get("impact"),
            mitigation=raw.get("mitigation"),
            active=raw.get("active"),
            verified=raw.get("verified"),
            product=product_name,
            endpoint=", ".join(endpoints) if endpoints else None,
            date=raw.get("date"),
            ticket_email=raw.get("ticket_email"),
            scanner_type=self._resolve_scanner_type(raw),
            category=self._string_or_none(raw.get("category")),
            cwe=raw.get("cwe"),
            cve=self._first_value(raw.get("cve") or raw.get("vulnerability_ids")),
            vuln_id_from_tool=self._string_or_none(raw.get("vuln_id_from_tool")),
            epss_score=raw.get("epss_score"),
            rule_id=self._string_or_none(raw.get("rule_id") or raw.get("unique_id_from_tool")),
            file_path=self._string_or_none(raw.get("file_path") or raw.get("file")),
            line=self._int_or_none(raw.get("line") or raw.get("line_number")),
            component_name=self._string_or_none(raw.get("component_name") or raw.get("component")),
            component_version=self._string_or_none(raw.get("component_version")),
            fixed_version=self._string_or_none(
                raw.get("fixed_version")
                or raw.get("fix_version")
                or raw.get("planned_remediation_version")
            ),
            cvss_score=(
                raw["cvssv3_score"]
                if raw.get("cvssv3_score") is not None
                else raw.get("cvss_score")
            ),
            repository=self._string_or_none(raw.get("repository") or raw.get("repo")),
            secret_type=self._string_or_none(raw.get("secret_type")),
            fingerprint=self._string_or_none(
                raw.get("fingerprint")
                or raw.get("hash_code")
                or raw.get("unique_id_from_tool")
            ),
            container_image=self._string_or_none(
                raw.get("container_image") or raw.get("image_name")
            ),
            http_method=self._string_or_none(
                raw.get("http_method") or raw.get("method")
            ),
            parameter=self._string_or_none(raw.get("parameter") or raw.get("param")),
            resource=self._string_or_none(
                raw.get("resource")
                or raw.get("resource_id")
                or raw.get("resource_arn")
                or raw.get("asset")
            ),
            resource_type=self._string_or_none(raw.get("resource_type")),
            aws_account_id=self._string_or_none(
                raw.get("aws_account_id") or raw.get("account_id")
            ),
            region=self._string_or_none(raw.get("region") or raw.get("aws_region")),
            compliance_status=self._string_or_none(raw.get("compliance_status")),
        )

    def _extract_endpoint_values(self, raw_endpoints: list) -> list[str]:
        """Normalize supported endpoint objects and strings into display values."""
        endpoints: list[str] = []
        for endpoint in raw_endpoints:
            if isinstance(endpoint, dict):
                host = endpoint.get("host") or ""
                path = endpoint.get("path") or ""
                value = f"{host}{path}"
            elif isinstance(endpoint, str):
                value = endpoint
            else:
                logger.debug(
                    "Skipping unsupported DefectDojo endpoint value",
                    extra={"endpoint_type": type(endpoint).__name__},
                )
                continue

            if value:
                endpoints.append(value)
        return endpoints

    def _resolve_scanner_type(self, raw: dict) -> str | None:
        """Resolve the scanner name from inline data or DefectDojo Test Type IDs."""
        for value in (
            raw.get("scanner_type"),
            raw.get("test_type"),
            raw.get("found_by"),
        ):
            candidates = value if isinstance(value, list) else [value]
            for candidate in candidates:
                if isinstance(candidate, str) and candidate.strip():
                    return candidate.strip()
                if isinstance(candidate, dict):
                    name = candidate.get("name")
                    if isinstance(name, str) and name.strip():
                        return name.strip()
                test_type_id = self._extract_id(candidate)
                if test_type_id is None:
                    continue
                try:
                    if test_type_id not in self._test_type_cache:
                        self._test_type_cache[test_type_id] = self._get_json(
                            f"api/v2/test_types/{test_type_id}/"
                        )
                    name = self._test_type_cache[test_type_id].get("name")
                    if isinstance(name, str) and name.strip():
                        return name.strip()
                except requests.RequestException as error:
                    logger.warning(
                        "Could not resolve DefectDojo Test Type",
                        extra={"test_type_id": test_type_id, "error_message": str(error)},
                    )
        return None

    def _resolve_product_name(self, raw: dict) -> str | None:
        """Resolve product name directly or through test and engagement links."""
        product = raw.get("product")
        if isinstance(product, dict) and product.get("name"):
            return product["name"]
        if isinstance(product, int):
            return self._get_product_name(product)

        test_id = self._extract_id(raw.get("test"))
        if test_id is None:
            return None

        try:
            test = self._get_test(test_id)
            engagement_id = self._extract_id(test.get("engagement"))
            if engagement_id is None:
                return None
            engagement = self._get_engagement(engagement_id)
            product_id = self._extract_id(engagement.get("product"))
            if product_id is None:
                return None
            return self._get_product_name(product_id)
        except Exception as error:
            logger.warning(
                "Could not resolve product from DefectDojo test/engagement",
                extra={"finding_id": raw.get("id"), "error_message": str(error)},
            )
            return None

    def _extract_id(self, value: object) -> int | None:
        """Extract an integer ID from an API integer or object reference."""
        if isinstance(value, int):
            return value
        if isinstance(value, dict) and isinstance(value.get("id"), int):
            return value["id"]
        return None

    def _get_test(self, test_id: int) -> dict:
        """Return a cached DefectDojo test resource."""
        if test_id not in self._test_cache:
            self._test_cache[test_id] = self._get_json(f"api/v2/tests/{test_id}/")
        return self._test_cache[test_id]

    def _get_engagement(self, engagement_id: int) -> dict:
        """Return a cached DefectDojo engagement resource."""
        if engagement_id not in self._engagement_cache:
            self._engagement_cache[engagement_id] = self._get_json(
                f"api/v2/engagements/{engagement_id}/"
            )
        return self._engagement_cache[engagement_id]

    def _get_product_name(self, product_id: int) -> str | None:
        """Resolve and cache a DefectDojo product name by ID."""
        if product_id not in self._product_cache:
            self._product_cache[product_id] = self._get_json(f"api/v2/products/{product_id}/")
        return self._product_cache[product_id].get("name")

    def _string_or_none(self, value: object) -> str | None:
        """Convert a non-empty API value to string."""
        if value in (None, ""):
            return None
        return str(value)

    def _int_or_none(self, value: object) -> int | None:
        """Convert a non-empty API value to integer when possible."""
        try:
            return int(value) if value not in (None, "") else None
        except (TypeError, ValueError):
            return None

    def _first_value(self, value: object) -> str | None:
        """Extract the first useful identifier from list, dict, or scalar values."""
        if isinstance(value, list):
            if not value:
                return None
            return self._first_value(value[0])
        if isinstance(value, dict):
            if not value:
                return None
            for key in ("vulnerability_id", "cve", "name", "id"):
                if value.get(key):
                    return self._string_or_none(value[key])
            return None
        return self._string_or_none(value)
