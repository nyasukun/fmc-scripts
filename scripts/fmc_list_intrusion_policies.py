#!/usr/bin/env python3
"""
List Cisco FMC Snort intrusion policy IDs and names.

Example:
  export FMC_HOST="https://fmc.example.local"
  export FMC_USERNAME="admin"
  export FMC_PASSWORD="..."

  ./scripts/fmc_list_intrusion_policies.py --insecure

Notes:
  - If --domain-uuid / FMC_DOMAIN_UUID is omitted, the script uses the
    DOMAIN_UUID header returned by POST /api/fmc_platform/v1/auth/generatetoken.
  - Use the printed "id" value as --intrusion-policy-id for
    scripts/fmc_upload_enable_snort3_rules.py.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from fmc_upload_enable_snort3_rules import FmcClient, get_all_items


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="List FMC intrusion policy IDs and names.")
    parser.add_argument("--host", default=os.getenv("FMC_HOST"), help="FMC base URL, e.g. https://fmc.example.local")
    parser.add_argument("--username", default=os.getenv("FMC_USERNAME"), help="FMC username")
    parser.add_argument("--password", default=os.getenv("FMC_PASSWORD"), help="FMC password")
    parser.add_argument(
        "--domain-uuid",
        default=os.getenv("FMC_DOMAIN_UUID"),
        help="FMC domain UUID. If omitted, use DOMAIN_UUID from the auth response header.",
    )
    parser.add_argument("--timeout", type=int, default=int(os.getenv("FMC_TIMEOUT", "120")))
    parser.add_argument("--retries", type=int, default=int(os.getenv("FMC_RETRIES", "3")))
    parser.add_argument("--insecure", action="store_true", help="Disable TLS certificate verification")
    parser.add_argument("--json", action="store_true", help="Print JSON instead of a table")
    return parser


def require_args(args: argparse.Namespace) -> None:
    missing = [name for name in ("host", "username", "password") if not getattr(args, name)]
    if missing:
        pretty = ", ".join("--" + name.replace("_", "-") for name in missing)
        raise SystemExit(f"Missing required arguments or environment variables: {pretty}")


def normalize_policy(item: dict[str, Any]) -> dict[str, Any]:
    base_policy = item.get("basePolicy") or {}
    metadata = item.get("metadata") or {}
    return {
        "id": item.get("id", ""),
        "name": item.get("name", ""),
        "type": item.get("type", ""),
        "inspectionMode": item.get("inspectionMode", ""),
        "snortEngine": item.get("snortEngine", ""),
        "isSystemDefined": item.get("isSystemDefined", metadata.get("isSystemDefined", "")),
        "basePolicyName": base_policy.get("name", ""),
    }


def print_table(rows: list[dict[str, Any]]) -> None:
    columns = [
        ("name", "Name"),
        ("id", "ID"),
        ("inspectionMode", "Inspection"),
        ("snortEngine", "Engine"),
        ("basePolicyName", "Base Policy"),
    ]
    widths = {
        key: max(len(title), *(len(str(row.get(key, ""))) for row in rows))
        for key, title in columns
    }
    header = "  ".join(title.ljust(widths[key]) for key, title in columns)
    print(header)
    print("  ".join("-" * widths[key] for key, _ in columns))
    for row in rows:
        print("  ".join(str(row.get(key, "")).ljust(widths[key]) for key, _ in columns))


def main() -> int:
    args = build_parser().parse_args()
    require_args(args)

    client = FmcClient(
        args.host,
        args.username,
        args.password,
        verify_tls=not args.insecure,
        timeout=args.timeout,
        retries=args.retries,
    )
    client.authenticate()
    domain_uuid = args.domain_uuid or client.domain_uuid
    if not domain_uuid:
        raise SystemExit("DOMAIN_UUID was not provided and was not present in the auth response headers.")

    path = f"/api/fmc_config/v1/domain/{domain_uuid}/policy/intrusionpolicies"
    rows = [normalize_policy(item) for item in get_all_items(client, path)]
    rows.sort(key=lambda row: (str(row.get("name", "")).lower(), str(row.get("id", ""))))

    if args.json:
        print(json.dumps({"domainUUID": domain_uuid, "items": rows}, ensure_ascii=False, indent=2))
    else:
        print(f"Domain UUID: {domain_uuid}")
        print_table(rows)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[error] interrupted", file=sys.stderr)
        raise SystemExit(130)
