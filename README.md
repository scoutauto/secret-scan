# secret-scan

Finds likely secrets (AWS keys, GitHub and Slack tokens, Stripe live keys, private key blocks, and `api_key=`/`password=` style assignments) in files before you commit or share them.

    python3 secret_scan.py path/to/repo

- Exit code 0 means nothing found, 1 means findings, 2 means usage error.
- Standard library only, Python 3.8+. Skips `.git`, `node_modules`, and binary files.
- Pattern-based: expect some false positives. Review each hit.
- Tested on a sample file with planted fake keys: both were flagged.
