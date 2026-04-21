#!/usr/bin/env python3
"""
Upload Snort 3 custom rules to Cisco FMC and enable them in an intrusion policy.

Example:
  export FMC_HOST="https://fmc.example.local"
  export FMC_USERNAME="admin"
  export FMC_PASSWORD="..."

  python3 scripts/fmc_upload_enable_snort3_rules.py \
    --rule-file ./custom.rules \
    --intrusion-policy-id 0697F32F-AD3F-0ed3-0000-004294971093 \
    --rule-group-name CUSTOM_RULES \
    --create-rule-group \
    --action ALERT \
    --insecure

How to get UUIDs:
  DOMAIN_UUID:
    Usually you do not need to set FMC_DOMAIN_UUID. This script reads it
    automatically from the response headers returned by:
      POST /api/fmc_platform/v1/auth/generatetoken

    To check the value manually:
      curl -sk -i -u 'USER:PASSWORD' -X POST \
        https://FMC/api/fmc_platform/v1/auth/generatetoken \
      | grep -i DOMAIN_UUID

    Use --domain-uuid or FMC_DOMAIN_UUID only when you explicitly want to
    target a different domain than the one returned by authentication.

  intrusion-policy-id:
    Run scripts/fmc_list_intrusion_policies.py. It calls
    GET /api/fmc_config/v1/domain/{domainUUID}/policy/intrusionpolicies
    and prints the policy name and id.
    You can also find it in the FMC GUI URL after opening the policy:
      Policies > Access Control > Intrusion > open target policy

  rule-group-id:
    This script can look up a group by --rule-group-name, or create it with
    --create-rule-group. To inspect it manually, use:
      Objects > Intrusion Rules > Snort 3 All Rules > Local Rules

How to confirm upload and enablement in the FMC GUI:
  Uploaded custom rules:
    Objects > Intrusion Rules > Snort 3 All Rules, then expand Local Rules
    and open the rule group used by --rule-group-name / --rule-group-id.
    Check the SID/msg from custom.rules.

  Enabled in the target intrusion policy:
    Policies > Access Control > Intrusion, open the target policy, click the
    Snort 3 version, then check the custom Local Rules group and/or
    Rule Overrides > Overridden Rules for the selected action.

  Deployment:
    Uploading/enabling creates pending changes. Deploy from:
      Deploy > Deployment
"""

from __future__ import annotations

import argparse
import base64
import json
import mimetypes
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from pathlib import Path
from typing import Any


RULE_ID_RE = re.compile(r"\b(?:(?P<key>gid|sid)\s*:\s*(?P<value>\d+))\s*;", re.IGNORECASE)
VALID_ACTIONS = (
    "ALERT",
    "BLOCK",
    "DROP",
    "DISABLE",
    "PASS",
    "REJECT",
    "REACT",
    "REWRITE",
    "DEFAULT",
)
VALID_IMPORT_MODES = ("MERGE", "REPLACE")
VALID_GROUP_LEVELS = ("LEVEL_1", "LEVEL_2", "LEVEL_3", "LEVEL_4", "DISABLED", "DEFAULT")


class FmcApiError(RuntimeError):
    def __init__(self, method: str, path: str, status: int, body: str):
        self.method = method
        self.path = path
        self.status = status
        self.body = body
        super().__init__(f"{method} {path} failed with HTTP {status}: {body[:800]}")


class FmcClient:
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        verify_tls: bool = True,
        timeout: int = 120,
        retries: int = 3,
    ) -> None:
        self.host = host.rstrip("/")
        self.username = username
        self.password = password
        self.timeout = timeout
        self.retries = retries
        self.token: str | None = None
        self.auth_headers: dict[str, str] = {}
        self.domain_uuid: str | None = None
        self.ssl_context = None if verify_tls else ssl._create_unverified_context()

    def authenticate(self) -> None:
        credentials = f"{self.username}:{self.password}".encode("utf-8")
        headers = {
            "Authorization": "Basic " + base64.b64encode(credentials).decode("ascii"),
            "Accept": "application/json",
        }
        status, response_headers, body = self._raw_request(
            "POST",
            "/api/fmc_platform/v1/auth/generatetoken",
            headers=headers,
            body=b"",
            retry_auth=False,
        )
        if status not in (200, 201, 202, 204):
            raise FmcApiError("POST", "/api/fmc_platform/v1/auth/generatetoken", status, body)
        token = response_headers.get("x-auth-access-token")
        if not token:
            raise RuntimeError("Authentication succeeded but X-auth-access-token was not returned.")
        self.token = token
        self.auth_headers = response_headers
        self.domain_uuid = response_headers.get("domain_uuid") or response_headers.get("global")

    def get_json(self, path: str, query: dict[str, Any] | None = None) -> Any:
        return self.request_json("GET", path, query=query)

    def post_json(self, path: str, data: Any, query: dict[str, Any] | None = None) -> Any:
        return self.request_json("POST", path, query=query, data=data)

    def put_json(self, path: str, data: Any, query: dict[str, Any] | None = None) -> Any:
        return self.request_json("PUT", path, query=query, data=data)

    def delete_json(self, path: str, query: dict[str, Any] | None = None) -> Any:
        return self.request_json("DELETE", path, query=query)

    def request_json(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        data: Any | None = None,
        headers: dict[str, str] | None = None,
    ) -> Any:
        body = None
        request_headers = {
            "Accept": "application/json",
        }
        if data is not None:
            body = json.dumps(data).encode("utf-8")
            request_headers["Content-Type"] = "application/json"
        if headers:
            request_headers.update(headers)

        status, _, response_body = self._request(method, path, query=query, headers=request_headers, body=body)
        if status < 200 or status >= 300:
            raise FmcApiError(method, build_path(path, query), status, response_body)
        if not response_body.strip():
            return {}
        try:
            return json.loads(response_body)
        except json.JSONDecodeError as exc:
            raise RuntimeError(f"{method} {path} returned non-JSON response: {response_body[:800]}") from exc

    def post_multipart(
        self,
        path: str,
        *,
        fields: dict[str, str],
        files: dict[str, Path],
        query: dict[str, Any] | None = None,
    ) -> Any:
        boundary = "----fmc-snort3-" + uuid.uuid4().hex
        body = build_multipart_body(boundary, fields, files)
        headers = {
            "Accept": "application/json",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
        }
        status, _, response_body = self._request("POST", path, query=query, headers=headers, body=body)
        if status < 200 or status >= 300:
            raise FmcApiError("POST", build_path(path, query), status, response_body)
        if not response_body.strip():
            return {}
        return json.loads(response_body)

    def _request(
        self,
        method: str,
        path: str,
        *,
        query: dict[str, Any] | None = None,
        headers: dict[str, str] | None = None,
        body: bytes | None = None,
    ) -> tuple[int, dict[str, str], str]:
        if not self.token:
            self.authenticate()

        request_headers = dict(headers or {})
        request_headers["X-auth-access-token"] = self.token or ""
        status, response_headers, response_body = self._raw_request(
            method,
            build_path(path, query),
            headers=request_headers,
            body=body,
            retry_auth=True,
        )
        if status == 401:
            self.authenticate()
            request_headers["X-auth-access-token"] = self.token or ""
            status, response_headers, response_body = self._raw_request(
                method,
                build_path(path, query),
                headers=request_headers,
                body=body,
                retry_auth=False,
            )
        return status, response_headers, response_body

    def _raw_request(
        self,
        method: str,
        path: str,
        *,
        headers: dict[str, str],
        body: bytes | None,
        retry_auth: bool,
    ) -> tuple[int, dict[str, str], str]:
        url = self.host + path
        last_error: Exception | None = None
        attempts = self.retries if retry_auth else 1

        for attempt in range(1, attempts + 1):
            request = urllib.request.Request(url, data=body, headers=headers, method=method)
            try:
                with urllib.request.urlopen(
                    request,
                    timeout=self.timeout,
                    context=self.ssl_context,
                ) as response:
                    response_body = response.read().decode("utf-8", errors="replace")
                    return response.status, lower_headers(response.headers), response_body
            except urllib.error.HTTPError as exc:
                response_body = exc.read().decode("utf-8", errors="replace")
                return exc.code, lower_headers(exc.headers), response_body
            except urllib.error.URLError as exc:
                last_error = exc
                if attempt < attempts:
                    time.sleep(attempt)

        raise RuntimeError(f"{method} {url} failed after {attempts} attempts: {last_error}")


def lower_headers(headers: Any) -> dict[str, str]:
    return {key.lower(): value for key, value in headers.items()}


def build_path(path: str, query: dict[str, Any] | None = None) -> str:
    if not query:
        return path
    clean_query = {key: value for key, value in query.items() if value is not None}
    if not clean_query:
        return path
    return path + "?" + urllib.parse.urlencode(clean_query)


def build_multipart_body(boundary: str, fields: dict[str, str], files: dict[str, Path]) -> bytes:
    chunks: list[bytes] = []
    boundary_bytes = boundary.encode("ascii")

    for name, value in fields.items():
        chunks.append(b"--" + boundary_bytes + b"\r\n")
        chunks.append(f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode("utf-8"))
        chunks.append(str(value).encode("utf-8"))
        chunks.append(b"\r\n")

    for name, path in files.items():
        filename = path.name
        content_type = mimetypes.guess_type(filename)[0] or "application/octet-stream"
        chunks.append(b"--" + boundary_bytes + b"\r\n")
        chunks.append(
            (
                f'Content-Disposition: form-data; name="{name}"; filename="{filename}"\r\n'
                f"Content-Type: {content_type}\r\n\r\n"
            ).encode("utf-8")
        )
        chunks.append(path.read_bytes())
        chunks.append(b"\r\n")

    chunks.append(b"--" + boundary_bytes + b"--\r\n")
    return b"".join(chunks)


def parse_rule_ids_from_file(rule_file: Path, default_gid: int) -> list[tuple[int, int]]:
    found: list[tuple[int, int]] = []
    seen: set[tuple[int, int]] = set()
    for line in rule_file.read_text(encoding="utf-8", errors="replace").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        attrs: dict[str, int] = {}
        for match in RULE_ID_RE.finditer(stripped):
            attrs[match.group("key").lower()] = int(match.group("value"))
        sid = attrs.get("sid")
        gid = attrs.get("gid", default_gid)
        if sid is None:
            continue
        rule_id = (gid, sid)
        if rule_id not in seen:
            found.append(rule_id)
            seen.add(rule_id)
    return found


def parse_rule_ids_from_upload_result(result: dict[str, Any]) -> list[tuple[int, int]]:
    found: list[tuple[int, int]] = []
    seen: set[tuple[int, int]] = set()
    summary = result.get("summary") or {}
    for bucket in ("added", "updated", "skipped", "unassociated"):
        for value in (summary.get(bucket) or {}).get("rules") or []:
            match = re.fullmatch(r"\s*(\d+)\s*:\s*(\d+)\s*", str(value))
            if not match:
                continue
            rule_id = (int(match.group(1)), int(match.group(2)))
            if rule_id not in seen:
                found.append(rule_id)
                seen.add(rule_id)
    return found


def get_all_items(
    client: FmcClient,
    path: str,
    *,
    query: dict[str, Any] | None = None,
    limit: int = 1000,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    offset = 0
    while True:
        page_query = dict(query or {})
        page_query.update({"limit": limit, "offset": offset, "expanded": "true"})
        payload = client.get_json(path, page_query)
        page_items = payload.get("items") or []
        items.extend(page_items)
        count = payload.get("paging", {}).get("count", len(items))
        offset += len(page_items)
        if not page_items or offset >= count:
            break
    return items


def find_rule_group_by_name(client: FmcClient, domain_uuid: str, name: str) -> dict[str, Any] | None:
    path = f"/api/fmc_config/v1/domain/{domain_uuid}/object/intrusionrulegroups"
    candidates = get_all_items(client, path, query={"filter": f"name:{name}"})
    for item in candidates:
        if item.get("name") == name:
            return item
    return None


def ensure_rule_group(client: FmcClient, args: argparse.Namespace) -> dict[str, Any]:
    if args.rule_group_id:
        path = (
            f"/api/fmc_config/v1/domain/{args.domain_uuid}/object/intrusionrulegroups/"
            f"{args.rule_group_id}"
        )
        return client.get_json(path, {"expanded": "true"})

    if not args.rule_group_name:
        raise ValueError("Use --rule-group-id or --rule-group-name.")

    existing = find_rule_group_by_name(client, args.domain_uuid, args.rule_group_name)
    if existing:
        print(f"[rule-group] using existing group: {existing['name']} ({existing['id']})")
        return existing

    if not args.create_rule_group:
        raise RuntimeError(
            f"Rule group '{args.rule_group_name}' was not found. "
            "Re-run with --create-rule-group to create it."
        )

    path = f"/api/fmc_config/v1/domain/{args.domain_uuid}/object/intrusionrulegroups"
    payload = {
        "name": args.rule_group_name,
        "description": args.rule_group_description or f"Custom Snort 3 rules: {args.rule_group_name}",
        "type": "IntrusionRuleGroup",
    }
    created = client.post_json(path, payload)
    print(f"[rule-group] created group: {created['name']} ({created['id']})")
    return created


def upload_rules(client: FmcClient, args: argparse.Namespace, rule_group: dict[str, Any]) -> dict[str, Any]:
    fields = {
        "ruleGroups": rule_group["id"],
        "ruleImportMode": args.import_mode,
        "validateOnly": "true" if args.validate_only else "false",
    }
    if args.rule_comment:
        fields["ruleComment"] = args.rule_comment
    path = f"/api/fmc_config/v1/domain/{args.domain_uuid}/object/intrusionrulesupload"
    print(
        f"[upload] {args.rule_file} -> group={rule_group.get('name', rule_group['id'])} "
        f"mode={args.import_mode} validateOnly={args.validate_only}"
    )
    return client.post_multipart(path, fields=fields, files={"payloadFile": args.rule_file})


def add_rule_group_to_policy(client: FmcClient, args: argparse.Namespace, rule_group: dict[str, Any]) -> None:
    if args.skip_policy_rule_group:
        print("[policy-group] skipped by --skip-policy-rule-group")
        return

    path = (
        f"/api/fmc_config/v1/domain/{args.domain_uuid}/policy/intrusionpolicies/"
        f"{args.intrusion_policy_id}/intrusionrulegroups"
    )
    payload = {
        "id": rule_group["id"],
        "name": rule_group.get("name", args.rule_group_name or rule_group["id"]),
        "type": "IntrusionRuleGroup",
        "description": rule_group.get("description", ""),
        "defaultSecurityLevel": rule_group.get("defaultSecurityLevel", "DISABLED"),
        "overrideSecurityLevel": args.rule_group_security_level,
    }
    print(
        f"[policy-group] adding/updating group {payload['name']} in policy "
        f"{args.intrusion_policy_id} level={args.rule_group_security_level}"
    )
    client.put_json(path, [payload], {"bulk": "true"})


def find_intrusion_rule(client: FmcClient, domain_uuid: str, gid: int, sid: int) -> dict[str, Any]:
    path = f"/api/fmc_config/v1/domain/{domain_uuid}/object/intrusionrules"
    items = get_all_items(client, path, query={"filter": f"gid:{gid};sid:{sid}"})
    exact = [
        item
        for item in items
        if int(item.get("gid", -1)) == gid and int(item.get("sid", -1)) == sid
    ]
    if not exact:
        raise RuntimeError(f"Uploaded rule {gid}:{sid} was not found in FMC.")
    exact.sort(key=lambda item: int(item.get("revision") or 0), reverse=True)
    return exact[0]


def rule_update_payload(
    policy_rule: dict[str, Any],
    object_rule: dict[str, Any],
    *,
    action: str,
    comment: str | None = None,
) -> dict[str, Any]:
    merged = dict(object_rule)
    merged.update(policy_rule)
    payload: dict[str, Any] = {}
    allowed_keys = (
        "id",
        "type",
        "name",
        "gid",
        "sid",
        "revision",
        "msg",
        "description",
        "ruleData",
        "defaultState",
        "isSystemDefined",
    )

    for key in allowed_keys:
        if key in merged and merged[key] is not None:
            payload[key] = merged[key]

    if merged.get("ruleGroups"):
        payload["ruleGroups"] = [
            {
                "id": group["id"],
                "name": group.get("name", ""),
                "type": group.get("type", "IntrusionRuleGroup"),
            }
            for group in merged["ruleGroups"]
            if group.get("id")
        ]

    payload["type"] = payload.get("type", "IntrusionRule")
    payload["overrideState"] = action
    if comment:
        payload["newComments"] = [comment]
    return payload


def enable_rule_in_policy(
    client: FmcClient,
    args: argparse.Namespace,
    rule: dict[str, Any],
) -> dict[str, Any]:
    path = (
        f"/api/fmc_config/v1/domain/{args.domain_uuid}/policy/intrusionpolicies/"
        f"{args.intrusion_policy_id}/intrusionrules/{rule['id']}"
    )
    # FMC rejects query parameters for this GETBYID operation.
    policy_rule = client.get_json(path)
    display_name = policy_rule.get("name") or f"{rule.get('gid')}:{rule.get('sid')}"
    print(
        f"[enable] {display_name} ({rule['id']}) -> {args.action}"
    )
    payload = rule_update_payload(policy_rule, rule, action=args.action, comment=args.rule_comment)
    return client.put_json(path, payload)


def summarize_upload_result(result: dict[str, Any]) -> dict[str, int]:
    summary = result.get("summary") or {}
    counts: dict[str, int] = {}
    for key in ("added", "updated", "skipped", "deleted", "unassociated"):
        counts[key] = int((summary.get(key) or {}).get("count") or 0)
    return counts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Upload Snort 3 custom rules to Cisco FMC and enable them in an intrusion policy."
    )
    parser.add_argument("--host", default=os.getenv("FMC_HOST"), help="FMC base URL, e.g. https://fmc.example.local")
    parser.add_argument("--username", default=os.getenv("FMC_USERNAME"), help="FMC username")
    parser.add_argument("--password", default=os.getenv("FMC_PASSWORD"), help="FMC password")
    parser.add_argument(
        "--domain-uuid",
        default=os.getenv("FMC_DOMAIN_UUID"),
        help="FMC domain UUID. If omitted, use DOMAIN_UUID from the auth response header.",
    )
    parser.add_argument(
        "--intrusion-policy-id",
        default=os.getenv("FMC_INTRUSION_POLICY_ID"),
        help="Target Snort 3 intrusion policy UUID",
    )
    parser.add_argument("--rule-file", type=Path, required=True, help=".rules or .txt file to upload")
    parser.add_argument("--rule-group-id", default=os.getenv("FMC_RULE_GROUP_ID"), help="Existing rule group UUID")
    parser.add_argument("--rule-group-name", default=os.getenv("FMC_RULE_GROUP_NAME"), help="Rule group name")
    parser.add_argument("--rule-group-description", default=os.getenv("FMC_RULE_GROUP_DESCRIPTION"))
    parser.add_argument("--create-rule-group", action="store_true", help="Create --rule-group-name if missing")
    parser.add_argument(
        "--rule-group-security-level",
        choices=VALID_GROUP_LEVELS,
        default=os.getenv("FMC_RULE_GROUP_SECURITY_LEVEL", "LEVEL_1"),
        help="Policy override security level for the custom rule group",
    )
    parser.add_argument(
        "--skip-policy-rule-group",
        action="store_true",
        help="Do not add/update the rule group in the target intrusion policy",
    )
    parser.add_argument(
        "--action",
        choices=VALID_ACTIONS,
        default=os.getenv("FMC_SNORT3_RULE_ACTION", "ALERT"),
        help="Rule override action in the target intrusion policy",
    )
    parser.add_argument(
        "--import-mode",
        choices=VALID_IMPORT_MODES,
        default=os.getenv("FMC_SNORT3_IMPORT_MODE", "MERGE"),
        help="Rule import mode",
    )
    parser.add_argument("--rule-comment", default=os.getenv("FMC_SNORT3_RULE_COMMENT"))
    parser.add_argument("--validate-only", action="store_true", help="Validate the rule file without importing")
    parser.add_argument(
        "--default-gid",
        type=int,
        default=int(os.getenv("FMC_SNORT3_DEFAULT_GID", "2000")),
        help="GID to assume for local rules that omit gid in ruleData",
    )
    parser.add_argument("--timeout", type=int, default=int(os.getenv("FMC_TIMEOUT", "120")))
    parser.add_argument("--retries", type=int, default=int(os.getenv("FMC_RETRIES", "3")))
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument(
        "--summary-json",
        type=Path,
        help="Optional path to write a machine-readable run summary",
    )
    return parser


def validate_args(args: argparse.Namespace) -> None:
    missing = [
        name
        for name in ("host", "username", "password", "intrusion_policy_id")
        if not getattr(args, name)
    ]
    if missing:
        pretty = ", ".join("--" + name.replace("_", "-") for name in missing)
        raise SystemExit(f"Missing required arguments or environment variables: {pretty}")
    if not args.rule_file.exists():
        raise SystemExit(f"Rule file not found: {args.rule_file}")
    if args.rule_file.suffix.lower() not in (".rules", ".txt"):
        raise SystemExit("FMC Snort 3 upload supports .rules and .txt files.")
    if not args.rule_group_id and not args.rule_group_name:
        raise SystemExit("Use --rule-group-id or --rule-group-name.")
    if args.validate_only and not args.skip_policy_rule_group:
        print("[note] --validate-only set; policy group update and rule enablement will be skipped")
        args.skip_policy_rule_group = True


def resolve_domain_uuid(client: FmcClient, args: argparse.Namespace) -> str:
    if args.domain_uuid:
        return args.domain_uuid

    client.authenticate()
    if not client.domain_uuid:
        raise SystemExit("DOMAIN_UUID was not provided and was not present in the auth response headers.")

    args.domain_uuid = client.domain_uuid
    print(f"[auth] using DOMAIN_UUID from authentication response: {args.domain_uuid}")
    return args.domain_uuid


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    validate_args(args)

    client = FmcClient(
        args.host,
        args.username,
        args.password,
        verify_tls=not args.insecure,
        timeout=args.timeout,
        retries=args.retries,
    )
    resolve_domain_uuid(client, args)

    parsed_file_rule_ids = parse_rule_ids_from_file(args.rule_file, args.default_gid)
    print(f"[parse] found {len(parsed_file_rule_ids)} Snort rule IDs in {args.rule_file}")

    rule_group = ensure_rule_group(client, args)
    upload_result = upload_rules(client, args, rule_group)
    upload_counts = summarize_upload_result(upload_result)
    print(f"[upload] summary: {upload_counts}")

    if args.validate_only:
        if args.summary_json:
            write_summary(args.summary_json, {"upload": upload_result, "validateOnly": True})
        print("[done] validation completed; no rules were enabled")
        return 0

    add_rule_group_to_policy(client, args, rule_group)

    rule_ids = parse_rule_ids_from_upload_result(upload_result)
    if not rule_ids:
        rule_ids = parsed_file_rule_ids
    if not rule_ids:
        raise RuntimeError("No rule IDs were found in the upload response or rule file.")

    enabled_rules = []
    for gid, sid in rule_ids:
        rule = find_intrusion_rule(client, args.domain_uuid, gid, sid)
        enabled = enable_rule_in_policy(client, args, rule)
        enabled_rules.append(
            {
                "gid": gid,
                "sid": sid,
                "ruleId": rule["id"],
                "revision": rule.get("revision"),
                "overrideState": enabled.get("overrideState", args.action),
            }
        )

    summary = {
        "fmc": args.host,
        "domainUUID": args.domain_uuid,
        "intrusionPolicyId": args.intrusion_policy_id,
        "ruleGroup": {
            "id": rule_group["id"],
            "name": rule_group.get("name"),
        },
        "uploadCounts": upload_counts,
        "enabledRules": enabled_rules,
    }
    if args.summary_json:
        write_summary(args.summary_json, summary)

    print(json.dumps(summary, ensure_ascii=False, indent=2))
    print("[done] upload and policy rule enablement completed; deploy pending changes from FMC when ready")
    return 0


def write_summary(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"[summary] wrote {path}")


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[error] interrupted", file=sys.stderr)
        raise SystemExit(130)
