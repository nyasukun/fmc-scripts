#!/usr/bin/env python3
"""
Interactively inspect and delete Cisco FMC Snort 3 custom rules.

Flow:
  1. Select an intrusion policy.
  2. Select a rule group in that policy.
  3. Select a custom rule in that group.
  4. Review details, then choose Back or Delete.

Each menu has Back. Press Ctrl-C at any time to exit.

Example:
  export FMC_HOST="https://fmc.example.local"
  export FMC_USERNAME="admin"
  export FMC_PASSWORD="..."

  ./scripts/fmc_delete_snort3_rule_interactive.py --insecure

Deletion API used:
  DELETE /api/fmc_config/v1/domain/{domainUUID}/object/intrusionrules/{objectId}

Fallback for FMC versions that reject DELETE-by-ID:
  DELETE /api/fmc_config/v1/domain/{domainUUID}/object/intrusionrules
    ?bulk=true&filter=ids:{objectId}

This script refuses to delete system-defined rules. It is intended for custom
Snort 3 rules uploaded through Objects > Intrusion Rules > Snort 3 All Rules.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Any

from fmc_list_intrusion_policies import normalize_policy
from fmc_upload_enable_snort3_rules import FmcApiError, FmcClient, get_all_items, rule_update_payload


BACK = "__BACK__"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Interactively inspect and delete FMC Snort 3 custom rules.")
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
    parser.add_argument(
        "--include-system-groups",
        action="store_true",
        help="Show system-defined rule groups too. Deletion of system-defined rules is still blocked.",
    )
    return parser


def require_args(args: argparse.Namespace) -> None:
    missing = [name for name in ("host", "username", "password") if not getattr(args, name)]
    if missing:
        pretty = ", ".join("--" + name.replace("_", "-") for name in missing)
        raise SystemExit(f"Missing required arguments or environment variables: {pretty}")


def resolve_domain_uuid(client: FmcClient, requested: str | None) -> str:
    if requested:
        return requested
    client.authenticate()
    if not client.domain_uuid:
        raise SystemExit("DOMAIN_UUID was not provided and was not present in the auth response headers.")
    print(f"[auth] using DOMAIN_UUID from authentication response: {client.domain_uuid}")
    return client.domain_uuid


def choose(title: str, rows: list[dict[str, Any]], formatter) -> dict[str, Any] | str:
    while True:
        print()
        print(title)
        print("-" * len(title))
        for index, row in enumerate(rows, start=1):
            print(f"{index:>3}. {formatter(row)}")
        print("  b. Back")
        answer = input("> ").strip().lower()
        if answer in ("b", "back"):
            return BACK
        if answer.isdigit():
            number = int(answer)
            if 1 <= number <= len(rows):
                return rows[number - 1]
        print("Invalid choice. Enter a number or b.")


def choose_action() -> str:
    while True:
        print()
        print("Action")
        print("------")
        print("  1. Back")
        print("  2. Delete")
        answer = input("> ").strip().lower()
        if answer in ("1", "b", "back"):
            return "back"
        if answer in ("2", "d", "delete"):
            return "delete"
        print("Invalid choice. Enter 1/Back or 2/Delete.")


def confirm_delete(rule: dict[str, Any]) -> bool:
    expected = f"{rule.get('gid')}:{rule.get('sid')}"
    print()
    print(f'Type "{expected}" to confirm deletion, or press Enter to cancel.')
    return input("> ").strip() == expected


def list_intrusion_policies(client: FmcClient, domain_uuid: str) -> list[dict[str, Any]]:
    path = f"/api/fmc_config/v1/domain/{domain_uuid}/policy/intrusionpolicies"
    rows = [normalize_policy(item) for item in get_all_items(client, path)]
    rows.sort(key=lambda row: (str(row.get("name", "")).lower(), str(row.get("id", ""))))
    return rows


def list_policy_rule_groups(
    client: FmcClient,
    domain_uuid: str,
    policy_id: str,
    *,
    include_system_groups: bool,
) -> list[dict[str, Any]]:
    path = f"/api/fmc_config/v1/domain/{domain_uuid}/policy/intrusionpolicies/{policy_id}/intrusionrulegroups"
    rows = get_all_items(client, path)
    if not include_system_groups:
        rows = [row for row in rows if not bool(row.get("isSystemDefined"))]
    rows.sort(key=lambda row: (str(row.get("name", "")).lower(), str(row.get("id", ""))))
    return rows


def list_custom_rules_for_group(client: FmcClient, domain_uuid: str, group: dict[str, Any]) -> list[dict[str, Any]]:
    path = f"/api/fmc_config/v1/domain/{domain_uuid}/object/intrusionrules"
    rows = get_all_items(client, path, query={"filter": "isSystemDefined:false"})
    group_id = group.get("id")
    group_name = group.get("name")
    filtered = []
    for row in rows:
        for rule_group in row.get("ruleGroups") or []:
            if rule_group.get("id") == group_id or rule_group.get("name") == group_name:
                filtered.append(row)
                break
    filtered.sort(key=lambda row: (int(row.get("gid", 0)), int(row.get("sid", 0)), int(row.get("revision", 0))))
    return filtered


def get_rule_detail(client: FmcClient, domain_uuid: str, rule_id: str) -> dict[str, Any]:
    path = f"/api/fmc_config/v1/domain/{domain_uuid}/object/intrusionrules/{rule_id}"
    return client.get_json(path)


def delete_custom_rule(client: FmcClient, domain_uuid: str, rule: dict[str, Any]) -> Any:
    if bool(rule.get("isSystemDefined")):
        raise RuntimeError("Refusing to delete a system-defined rule.")
    rule_id = rule.get("id")
    if not rule_id:
        raise RuntimeError("Rule has no object id; refusing to delete.")

    by_id_path = f"/api/fmc_config/v1/domain/{domain_uuid}/object/intrusionrules/{rule_id}"
    try:
        return client.delete_json(by_id_path)
    except FmcApiError as by_id_error:
        if by_id_error.status not in (400, 404, 405, 422):
            raise

        bulk_path = f"/api/fmc_config/v1/domain/{domain_uuid}/object/intrusionrules"
        try:
            return client.delete_json(bulk_path, {"bulk": "true", "filter": f"ids:{rule_id}"})
        except FmcApiError as bulk_error:
            raise RuntimeError(
                "Delete failed by object ID and bulk ids filter. "
                f"DELETE-by-ID returned HTTP {by_id_error.status}: {by_id_error.body[:300]} "
                f"Bulk returned HTTP {bulk_error.status}: {bulk_error.body[:300]}"
            ) from bulk_error


def is_object_in_use_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return "being used" in text or "object in use" in text or "cannot be deleted" in text


def print_policy_impact(title: str, refs: list[dict[str, Any]]) -> None:
    print(f"[impact] {title}: {len(refs)} policies")
    for ref in refs:
        details = []
        if ref.get("overrideState"):
            details.append(f"overrideState={ref['overrideState']}")
        if ref.get("defaultState"):
            details.append(f"defaultState={ref['defaultState']}")
        if ref.get("overrideSecurityLevel"):
            details.append(f"overrideSecurityLevel={ref['overrideSecurityLevel']}")
        if ref.get("defaultSecurityLevel"):
            details.append(f"defaultSecurityLevel={ref['defaultSecurityLevel']}")
        suffix = " " + " ".join(details) if details else ""
        print(f"  - {ref.get('name', '')} ({ref.get('id', '')}){suffix}")


def policy_rule_override_refs(
    client: FmcClient,
    domain_uuid: str,
    policies: list[dict[str, Any]],
    rule: dict[str, Any],
) -> list[dict[str, Any]]:
    refs = []
    for policy in policies:
        try:
            policy_rule = client.get_json(policy_rule_path(domain_uuid, policy["id"], rule["id"]))
        except FmcApiError as exc:
            if exc.status in (400, 404, 422):
                continue
            raise
        override_state = str(policy_rule.get("overrideState") or "").upper()
        if override_state and override_state != "DEFAULT":
            refs.append(
                {
                    "id": policy["id"],
                    "name": policy.get("name"),
                    "overrideState": policy_rule.get("overrideState"),
                    "defaultState": policy_rule.get("defaultState"),
                }
            )
    return refs


def policy_rule_group_override_refs(
    client: FmcClient,
    domain_uuid: str,
    policies: list[dict[str, Any]],
    group: dict[str, Any],
) -> list[dict[str, Any]]:
    refs = []
    group_id = group.get("id")
    group_name = group.get("name")
    for policy in policies:
        groups = list_policy_rule_groups(
            client,
            domain_uuid,
            policy["id"],
            include_system_groups=True,
        )
        for policy_group in groups:
            if policy_group.get("id") != group_id and policy_group.get("name") != group_name:
                continue
            override_level = str(policy_group.get("overrideSecurityLevel") or "").upper()
            if override_level and override_level != "DEFAULT":
                refs.append(
                    {
                        "id": policy["id"],
                        "name": policy.get("name"),
                        "overrideSecurityLevel": policy_group.get("overrideSecurityLevel"),
                        "defaultSecurityLevel": policy_group.get("defaultSecurityLevel"),
                    }
                )
            break
    return refs


def policy_rule_path(domain_uuid: str, policy_id: str, rule_id: str) -> str:
    return (
        f"/api/fmc_config/v1/domain/{domain_uuid}/policy/intrusionpolicies/"
        f"{policy_id}/intrusionrules/{rule_id}"
    )


def clear_policy_rule_override(
    client: FmcClient,
    domain_uuid: str,
    policy_id: str,
    rule: dict[str, Any],
) -> None:
    path = policy_rule_path(domain_uuid, policy_id, rule["id"])
    policy_rule = client.get_json(path)
    payload = rule_update_payload(policy_rule, rule, action="DEFAULT")
    print(f"[policy-cleanup] set {rule.get('gid')}:{rule.get('sid')} overrideState=DEFAULT")
    client.put_json(path, payload)


def policy_group_update_payload(group: dict[str, Any], level: str) -> dict[str, Any]:
    return {
        "id": group["id"],
        "name": group.get("name", ""),
        "type": group.get("type", "IntrusionRuleGroup"),
        "description": group.get("description", ""),
        "defaultSecurityLevel": group.get("defaultSecurityLevel", "DISABLED"),
        "overrideSecurityLevel": level,
    }


def reset_policy_rule_group(
    client: FmcClient,
    domain_uuid: str,
    policy_id: str,
    group: dict[str, Any],
) -> None:
    by_id_path = (
        f"/api/fmc_config/v1/domain/{domain_uuid}/policy/intrusionpolicies/"
        f"{policy_id}/intrusionrulegroups/{group['id']}"
    )
    collection_path = (
        f"/api/fmc_config/v1/domain/{domain_uuid}/policy/intrusionpolicies/"
        f"{policy_id}/intrusionrulegroups"
    )
    try:
        group_detail = client.get_json(by_id_path)
    except FmcApiError:
        group_detail = dict(group)
    payload = policy_group_update_payload({**group, **group_detail}, "DEFAULT")
    print(f"[policy-cleanup] set rule group {payload['name']} overrideSecurityLevel=DEFAULT")
    try:
        client.put_json(by_id_path, payload)
    except FmcApiError as by_id_error:
        if by_id_error.status not in (400, 404, 405, 422):
            raise
        client.put_json(collection_path, [payload], {"bulk": "true"})


def ask_yes_no(prompt: str, *, default: bool = False) -> bool:
    suffix = " [Y/n]" if default else " [y/N]"
    answer = input(prompt + suffix + " ").strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def delete_custom_rule_with_policy_cleanup(
    client: FmcClient,
    domain_uuid: str,
    policies: list[dict[str, Any]],
    policy: dict[str, Any],
    group: dict[str, Any],
    group_rules: list[dict[str, Any]],
    rule: dict[str, Any],
) -> Any:
    try:
        return delete_custom_rule(client, domain_uuid, rule)
    except Exception as first_error:
        if not is_object_in_use_error(first_error):
            raise

    print("[delete] rule is still referenced by policy; clearing the per-policy rule override first")
    rule_refs = policy_rule_override_refs(client, domain_uuid, policies, rule)
    print_policy_impact("Policies whose rule override would be cleared by DEFAULT", rule_refs)
    if not ask_yes_no("Set this rule override to DEFAULT in the selected policy and retry delete?"):
        raise RuntimeError("Delete cancelled before changing the selected policy rule override.")
    clear_policy_rule_override(client, domain_uuid, policy["id"], rule)
    try:
        return delete_custom_rule(client, domain_uuid, rule)
    except Exception as second_error:
        if not is_object_in_use_error(second_error):
            raise

    group_refs = policy_rule_group_override_refs(client, domain_uuid, policies, group)
    print_policy_impact("Policies whose rule group override would be cleared by DEFAULT", group_refs)
    if len(group_rules) > 1:
        print(
            f"[delete] rule group {group.get('name')} has {len(group_rules)} custom rules. "
            "Resetting the group in the selected policy may affect the other rules."
        )
    if not ask_yes_no("Set this rule group to DEFAULT in the selected policy and retry delete?"):
        raise RuntimeError("Delete cancelled before changing the selected policy rule group.")

    reset_policy_rule_group(client, domain_uuid, policy["id"], group)
    try:
        return delete_custom_rule(client, domain_uuid, rule)
    except Exception as third_error:
        if not is_object_in_use_error(third_error):
            raise

    print("[delete] rule is still referenced; trying rule group overrideSecurityLevel=DISABLED")
    by_id_path = (
        f"/api/fmc_config/v1/domain/{domain_uuid}/policy/intrusionpolicies/"
        f"{policy['id']}/intrusionrulegroups/{group['id']}"
    )
    collection_path = (
        f"/api/fmc_config/v1/domain/{domain_uuid}/policy/intrusionpolicies/"
        f"{policy['id']}/intrusionrulegroups"
    )
    payload = policy_group_update_payload(group, "DISABLED")
    try:
        client.put_json(by_id_path, payload)
    except FmcApiError as by_id_error:
        if by_id_error.status not in (400, 404, 405, 422):
            raise
        client.put_json(collection_path, [payload], {"bulk": "true"})
    return delete_custom_rule(client, domain_uuid, rule)


def policy_label(row: dict[str, Any]) -> str:
    details = []
    if row.get("inspectionMode"):
        details.append(str(row["inspectionMode"]))
    if row.get("snortEngine"):
        details.append(str(row["snortEngine"]))
    suffix = f" [{', '.join(details)}]" if details else ""
    return f"{row.get('name', '')}  id={row.get('id', '')}{suffix}"


def group_label(row: dict[str, Any]) -> str:
    bits = [f"id={row.get('id', '')}"]
    if row.get("overrideSecurityLevel"):
        bits.append(f"override={row['overrideSecurityLevel']}")
    if row.get("defaultSecurityLevel"):
        bits.append(f"default={row['defaultSecurityLevel']}")
    if row.get("totalRuleCount") is not None:
        bits.append(f"rules={row['totalRuleCount']}")
    if row.get("isSystemDefined"):
        bits.append("system")
    return f"{row.get('name', '')}  " + " ".join(bits)


def rule_label(row: dict[str, Any]) -> str:
    revision = row.get("revision", "")
    msg = row.get("msg") or row.get("description") or ""
    state = row.get("overrideState") or row.get("defaultState") or ""
    return f"{row.get('gid')}:{row.get('sid')} rev={revision} state={state}  {msg}"


def print_rule_detail(rule: dict[str, Any]) -> None:
    visible = {
        "id": rule.get("id"),
        "name": rule.get("name"),
        "gid": rule.get("gid"),
        "sid": rule.get("sid"),
        "revision": rule.get("revision"),
        "msg": rule.get("msg"),
        "defaultState": rule.get("defaultState"),
        "overrideState": rule.get("overrideState"),
        "isSystemDefined": rule.get("isSystemDefined"),
        "ruleGroups": [
            {"id": group.get("id"), "name": group.get("name"), "type": group.get("type")}
            for group in rule.get("ruleGroups") or []
        ],
        "ruleData": rule.get("ruleData"),
    }
    print()
    print("Rule Detail")
    print("-----------")
    print(json.dumps(visible, ensure_ascii=False, indent=2))


def interactive_loop(client: FmcClient, domain_uuid: str, args: argparse.Namespace) -> None:
    policies_cache: list[dict[str, Any]] | None = None
    groups_cache: dict[str, list[dict[str, Any]]] = {}
    rules_cache: dict[str, list[dict[str, Any]]] = {}

    while True:
        if policies_cache is None:
            policies_cache = list_intrusion_policies(client, domain_uuid)
        selected_policy = choose("Select Intrusion Policy", policies_cache, policy_label)
        if selected_policy == BACK:
            continue

        policy_id = selected_policy["id"]
        while True:
            if policy_id not in groups_cache:
                groups_cache[policy_id] = list_policy_rule_groups(
                    client,
                    domain_uuid,
                    policy_id,
                    include_system_groups=args.include_system_groups,
                )
            groups = groups_cache[policy_id]
            if not groups:
                print("No rule groups found. Use --include-system-groups to show system-defined groups.")
                break

            selected_group = choose(
                f"Select Rule Group for {selected_policy.get('name')}",
                groups,
                group_label,
            )
            if selected_group == BACK:
                break

            group_id = selected_group["id"]
            while True:
                if group_id not in rules_cache:
                    rules_cache[group_id] = list_custom_rules_for_group(client, domain_uuid, selected_group)
                rules = rules_cache[group_id]
                if not rules:
                    print("No custom rules found in this group.")
                    break

                selected_rule = choose(
                    f"Select Custom Rule in {selected_group.get('name')}",
                    rules,
                    rule_label,
                )
                if selected_rule == BACK:
                    break

                while True:
                    detail = get_rule_detail(client, domain_uuid, selected_rule["id"])
                    print_rule_detail(detail)
                    action = choose_action()
                    if action == "back":
                        break

                    if detail.get("isSystemDefined"):
                        print("This rule is system-defined. Delete is blocked.")
                        continue
                    if not confirm_delete(detail):
                        print("Delete cancelled.")
                        continue

                    try:
                        result = delete_custom_rule_with_policy_cleanup(
                            client,
                            domain_uuid,
                            policies_cache,
                            selected_policy,
                            selected_group,
                            rules,
                            detail,
                        )
                    except Exception as exc:
                        print(f"[delete] failed: {exc}")
                        continue

                    print("[delete] completed")
                    if result:
                        print(json.dumps(result, ensure_ascii=False, indent=2))
                    rules_cache.pop(group_id, None)
                    groups_cache.pop(policy_id, None)
                    break


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
    domain_uuid = resolve_domain_uuid(client, args.domain_uuid)
    interactive_loop(client, domain_uuid, args)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\n[exit] interrupted")
        raise SystemExit(130)
