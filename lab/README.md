diff --git a/lab/README.md b/lab/README.md
new file mode 100644
index 0000000000000000000000000000000000000000..ee4f1f60fd23f259d374c46238704ea3600152cd
--- /dev/null
+++ b/lab/README.md
@@ -0,0 +1,58 @@
+# Counterintelligence & Insider Threat Detection Lab
+
+This lab is a hands-on, synthetic environment for practicing insider threat detection workflows. It generates realistic user-activity monitoring (UAM) telemetry, enriches it with HR and access request context, and runs detection rules to produce actionable alerts.
+
+## What you'll do
+
+1. Generate synthetic UAM logs with both normal and anomalous activity.
+2. Correlate activity with HR records and sensitive asset metadata.
+3. Run detection logic and triage the resulting alerts.
+4. Capture findings and recommendations in a report template.
+
+## Quick start
+
+From the repository root:
+
+```bash
+python3 lab/simulate_activity.py
+python3 lab/detect_anomalies.py
+```
+
+Or run the wrapper script:
+
+```bash
+./lab/run_lab.sh
+```
+
+Outputs:
+- `data/uam_logs.jsonl` — synthetic activity logs
+- `data/alerts.json` — alert artifacts (JSON)
+- `data/alerts.md` — human-readable alert summary
+
+## Lab scenarios
+
+The simulation injects multiple suspicious behaviors to replicate insider threat patterns:
+
+- **Off-hours access** — logins between 20:00–06:00 UTC.
+- **Large data transfers** — bulk copies of sensitive files.
+- **Repeated failed logins** — brute-force or credential stuffing attempts.
+- **USB exfiltration** — file access within a removable media window.
+- **Unauthorized access** — low-clearance users touching high-sensitivity assets.
+- **Access without approval** — activity without an approved access request on record.
+
+Adjust thresholds and parameters in `lab/config.json` to create new cases.
+
+## Analyst workflow
+
+1. **Review alerts** in `data/alerts.md`.
+2. **Enrich context** by cross-referencing `data/hr_records.csv` and `data/access_requests.csv`.
+3. **Document findings** in `lab/report_template.md`.
+4. **Brief leadership** on detection gaps and recommended mitigations.
+
+## Cleanup
+
+Remove generated artifacts if you want to reset the lab:
+
+```bash
+rm -f data/uam_logs.jsonl data/alerts.json data/alerts.md
+```
