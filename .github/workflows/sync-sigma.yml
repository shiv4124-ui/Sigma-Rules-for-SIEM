name: Sync Sigma rules

on:
  schedule:
    - cron: "30 2 * * *"   # daily at 02:30 UTC (08:00 IST)
  workflow_dispatch:
    inputs:
      force:
        description: "Re-download even if upstream is unchanged"
        type: boolean
        default: false

permissions:
  contents: write

concurrency:
  group: sync-sigma
  cancel-in-progress: false

jobs:
  sync:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
          cache: pip

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Fetch Sigma rules
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          if [ "${{ github.event.inputs.force }}" = "true" ]; then
            python fetch_sigma_rules.py --force
          else
            python fetch_sigma_rules.py
          fi

      - name: Convert to expressions
        run: python convert_expressions.py

      - name: Commit changes
        run: |
          git config user.name "github-actions[bot]"
          git config user.email "41898282+github-actions[bot]@users.noreply.github.com"
          git add -A sigma
          if git diff --cached --quiet; then
            echo "No changes."
            exit 0
          fi
          COUNT=$(python -c "import json;print(json.load(open('sigma/metadata.json'))['indexed_rules'])")
          SHA=$(python -c "import json;print(json.load(open('sigma/metadata.json'))['upstream_commit'][:10])")
          git commit -m "Sync Sigma rules + expressions: ${COUNT} rules @ SigmaHQ/sigma ${SHA}"
          git push
