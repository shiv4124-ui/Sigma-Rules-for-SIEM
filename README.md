# Sigma-Rules-for-SIEM

Automatically fetches every Sigma detection rule from SigmaHQ/sigma
(https://github.com/SigmaHQ/sigma), stores them in this repo, and builds a searchable index.
A GitHub Action re-syncs daily at 08:00 IST.

## Output
- sigma/rules/ – all rule folders (core, emerging threats, threat hunting, compliance, DFIR, placeholder)
- sigma/index.json and sigma/index.csv – one entry per rule: id, title, level, status, logsource, tags, path
- sigma/stats.json – counts by folder, level, status, product, type and ATT&CK tactic
- sigma/metadata.json – upstream commit, fetch time, rule counts

## Run locally
    pip install -r requirements.txt
    python fetch_sigma_rules.py

## Manual sync
Actions → Sync Sigma rules → Run workflow

## License
Sigma rules are © their authors under the Detection Rule License (DRL) 1.1
(https://github.com/SigmaHQ/Detection-Rule-License), which requires attribution.
