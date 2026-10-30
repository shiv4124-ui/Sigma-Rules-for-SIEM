# Sigma Rule `status` Values

`status` documents how mature a rule is. It does not change how the rule runs.

| Status | Meaning |
|---|---|
| `stable` | Tested over time in several environments, few false positives. Safe to deploy broadly. |
| `test` | Fairly mature, some testing done, may still need tuning. |
| `experimental` | New or lightly tested. Could be noisy or miss cases. |
| `deprecated` | Replaced by another rule (see `related`). Don't use. |
| `unsupported` | Can't be used in its current form (e.g. needs special correlation). |

All rules in this repo start as `experimental`. To promote one:
1. Run it in alert-only / monitor mode for a couple of weeks.
2. Review hits and add exclusions for legitimate activity (provisioning scripts, IT admin accounts).
3. When it's quiet and accurate, change to `test`; after a longer period in production, `stable`.
