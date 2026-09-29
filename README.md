## Output
- sigma/rules/windows/ – Windows rules, grouped by log type (process_creation, security, powershell …)
- sigma/rules/linux/ and sigma/rules/macos/ – same structure for Linux and macOS
- sigma/rules/cloud/ – aws, azure, gcp, m365, okta, github …
- sigma/rules/network/ – zeek, cisco, fortinet, dns, firewall …
- sigma/rules/web/ – webserver and proxy rules
- sigma/rules/application/ – django, sql, jvm, kubernetes …
- sigma/rules/other/ – anything that doesn't fit a platform
- sigma/index.json and sigma/index.csv – every rule with platform, ruleset, level, status, tags, path
- sigma/stats.json – counts by platform, ruleset, level, status, product and ATT&CK tactic
