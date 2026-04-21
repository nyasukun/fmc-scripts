# FMC Snort 3 Scripts

Cisco FMC API utilities for Snort 3 custom rule operations.

## Contents

- `scripts/fmc_upload_enable_snort3_rules.py`
  - Upload a `.rules` or `.txt` Snort 3 custom rule file.
  - Create or reuse a custom rule group.
  - Add the group to a target intrusion policy.
  - Enable uploaded rules with an action such as `ALERT` or `BLOCK`.
- `scripts/fmc_list_intrusion_policies.py`
  - List intrusion policy names and UUIDs.
- `scripts/fmc_delete_snort3_rule_interactive.py`
  - Interactive rule inspection and deletion helper.
  - Shows intrusion policies, rule groups, and custom rules.
  - Displays the rule detail before deletion.
  - Supports `Back` at each menu and exits with `Ctrl-C`.
- `custom.rules`
  - Safe sample Snort 3 custom rule for upload testing.

## Environment

Set FMC connection details as environment variables:

```bash
export FMC_HOST="https://<fmc-host>"
export FMC_USERNAME="admin"
export FMC_PASSWORD="<password>"
```

`FMC_DOMAIN_UUID` is optional. The scripts normally read `DOMAIN_UUID` from the
FMC authentication response.

For lab FMCs with self-signed certificates, pass `--insecure`.

## List Intrusion Policies

```bash
./scripts/fmc_list_intrusion_policies.py --insecure
```

Use the printed `ID` as `--intrusion-policy-id`.

## Upload And Enable A Custom Rule

```bash
./scripts/fmc_upload_enable_snort3_rules.py \
  --rule-file ./custom.rules \
  --intrusion-policy-id <intrusion-policy-id> \
  --rule-group-name CUSTOM_RULES \
  --create-rule-group \
  --action ALERT \
  --insecure
```

After upload and enablement, deploy pending changes in FMC:

```text
Deploy > Deployment
```

## Confirm In FMC GUI

Uploaded custom rules:

```text
Objects > Intrusion Rules > Snort 3 All Rules > Local Rules
```

Policy enablement:

```text
Policies > Access Control > Intrusion > target policy > Snort 3 version
Rule Overrides > Overridden Rules
```

## Interactive Rule Delete

```bash
./scripts/fmc_delete_snort3_rule_interactive.py --insecure
```

The delete tool refuses to delete system-defined rules. If FMC reports that a
custom rule is still used by policies, the tool shows how many intrusion
policies would be affected before asking whether to set the selected policy
rule or rule group back to `DEFAULT`.

## Notes

- Do not commit real FMC passwords, tokens, private keys, or lab IPs.
- The scripts use only Python standard library modules.
- Deleting or enabling rules creates pending changes in FMC. Deploy explicitly
  when you are ready.
