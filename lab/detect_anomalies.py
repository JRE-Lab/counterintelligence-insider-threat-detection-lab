diff --git a/lab/detect_anomalies.py b/lab/detect_anomalies.py
new file mode 100755
index 0000000000000000000000000000000000000000..4943a0f52c162de9aec3a6da321e6b4aa34a4ae7
--- /dev/null
+++ b/lab/detect_anomalies.py
@@ -0,0 +1,214 @@
+#!/usr/bin/env python3
+"""Detect anomalies in synthetic UAM logs."""
+
+import argparse
+import csv
+import json
+from collections import defaultdict, deque
+from datetime import datetime, timezone
+from pathlib import Path
+
+ROOT = Path(__file__).resolve().parent.parent
+DATA_DIR = ROOT / "data"
+CONFIG_PATH = ROOT / "lab" / "config.json"
+
+CLEARANCE_LEVELS = {"Confidential": 1, "Secret": 2, "Top Secret": 3}
+
+
+def load_config(path: Path) -> dict:
+    with path.open("r", encoding="utf-8") as handle:
+        return json.load(handle)
+
+
+def load_csv(path: Path) -> list[dict]:
+    with path.open("r", encoding="utf-8") as handle:
+        return list(csv.DictReader(handle))
+
+
+def load_logs(path: Path) -> list[dict]:
+    logs = []
+    with path.open("r", encoding="utf-8") as handle:
+        for line in handle:
+            logs.append(json.loads(line))
+    return logs
+
+
+def parse_timestamp(value: str) -> datetime:
+    return datetime.fromisoformat(value).astimezone(timezone.utc)
+
+
+def build_context(
+    hr_records: list[dict],
+    assets: list[dict],
+    access_requests: list[dict],
+) -> tuple[dict, dict, dict]:
+    hr_by_user = {record["user_id"]: record for record in hr_records}
+    assets_by_id = {asset["asset_id"]: asset for asset in assets}
+    approvals = defaultdict(set)
+    for request in access_requests:
+        if request["status"].lower() == "approved":
+            approvals[request["user_id"]].add(request["asset_id"])
+    return hr_by_user, assets_by_id, approvals
+
+
+def detect_anomalies(
+    logs: list[dict],
+    hr_by_user: dict,
+    assets_by_id: dict,
+    approvals: dict,
+    cfg: dict,
+) -> list[dict]:
+    alerts: list[dict] = []
+    failed_logins = defaultdict(deque)
+    daily_file_access = defaultdict(lambda: defaultdict(int))
+    usb_events = defaultdict(deque)
+
+    for event in logs:
+        timestamp = parse_timestamp(event["timestamp"])
+        user_id = event["user_id"]
+        event_type = event["event_type"]
+
+        if event_type == "login" and event["status"] == "failed":
+            window = cfg["failed_login_window_minutes"]
+            failed_logins[user_id].append(timestamp)
+            while failed_logins[user_id] and (timestamp - failed_logins[user_id][0]).total_seconds() > window * 60:
+                failed_logins[user_id].popleft()
+            if len(failed_logins[user_id]) >= cfg["failed_login_threshold"]:
+                alerts.append(
+                    {
+                        "timestamp": event["timestamp"],
+                        "user_id": user_id,
+                        "alert_type": "Repeated failed logins",
+                        "details": f"{len(failed_logins[user_id])} failed logins in {window} minutes",
+                    }
+                )
+
+        if event_type == "login" and event["status"] == "success":
+            hour = timestamp.hour
+            if hour >= cfg["off_hours_start"] or hour < cfg["off_hours_end"]:
+                alerts.append(
+                    {
+                        "timestamp": event["timestamp"],
+                        "user_id": user_id,
+                        "alert_type": "Off-hours login",
+                        "details": f"Login at {hour:02d}:{timestamp.minute:02d} UTC",
+                    }
+                )
+
+        if event_type == "file_access":
+            date_key = timestamp.date().isoformat()
+            daily_file_access[user_id][date_key] += 1
+            if daily_file_access[user_id][date_key] > cfg["daily_file_access_threshold"]:
+                alerts.append(
+                    {
+                        "timestamp": event["timestamp"],
+                        "user_id": user_id,
+                        "alert_type": "High volume file access",
+                        "details": f"{daily_file_access[user_id][date_key]} file accesses on {date_key}",
+                    }
+                )
+
+            asset = assets_by_id.get(event["asset_id"], {})
+            if asset:
+                user_clearance = CLEARANCE_LEVELS.get(hr_by_user[user_id]["clearance"], 0)
+                asset_clearance = CLEARANCE_LEVELS.get(asset["required_clearance"], 0)
+                if user_clearance < asset_clearance:
+                    alerts.append(
+                        {
+                            "timestamp": event["timestamp"],
+                            "user_id": user_id,
+                            "alert_type": "Unauthorized sensitive access",
+                            "details": f"Accessed {asset['path']} requiring {asset['required_clearance']}",
+                        }
+                    )
+                if event["asset_id"] and event["asset_id"] not in approvals.get(user_id, set()):
+                    alerts.append(
+                        {
+                            "timestamp": event["timestamp"],
+                            "user_id": user_id,
+                            "alert_type": "Access without approved request",
+                            "details": f"No approved request for {asset['path']}",
+                        }
+                    )
+
+            if event.get("bytes_out", 0) and int(event["bytes_out"]) >= cfg["large_transfer_bytes"]:
+                alerts.append(
+                    {
+                        "timestamp": event["timestamp"],
+                        "user_id": user_id,
+                        "alert_type": "Large data transfer",
+                        "details": f"{event['bytes_out']} bytes copied from {event.get('asset_path')}",
+                    }
+                )
+
+        if event_type == "usb_insert":
+            usb_events[user_id].append(timestamp)
+            window = cfg["usb_exfil_window_minutes"]
+            while usb_events[user_id] and (timestamp - usb_events[user_id][0]).total_seconds() > window * 60:
+                usb_events[user_id].popleft()
+
+        if event_type == "file_access" and event.get("bytes_out", 0):
+            window = cfg["usb_exfil_window_minutes"]
+            for usb_time in usb_events[user_id]:
+                if 0 <= (timestamp - usb_time).total_seconds() <= window * 60:
+                    alerts.append(
+                        {
+                            "timestamp": event["timestamp"],
+                            "user_id": user_id,
+                            "alert_type": "Possible USB exfiltration",
+                            "details": "Large file access within USB insert window",
+                        }
+                    )
+                    break
+
+    return alerts
+
+
+def write_outputs(alerts: list[dict], output_dir: Path) -> None:
+    output_dir.mkdir(parents=True, exist_ok=True)
+    json_path = output_dir / "alerts.json"
+    md_path = output_dir / "alerts.md"
+
+    with json_path.open("w", encoding="utf-8") as handle:
+        json.dump(alerts, handle, indent=2)
+
+    with md_path.open("w", encoding="utf-8") as handle:
+        handle.write("# Insider Threat Alerts\n\n")
+        if not alerts:
+            handle.write("No alerts detected.\n")
+            return
+        summary = defaultdict(int)
+        for alert in alerts:
+            summary[alert["alert_type"]] += 1
+
+        handle.write("## Summary\\n\\n")
+        for alert_type, count in sorted(summary.items()):
+            handle.write(f"- {alert_type}: {count}\\n")
+        handle.write("\\n## Alerts\\n\\n")
+
+        for alert in alerts:
+            handle.write(f"- **{alert['alert_type']}** ({alert['timestamp']}) - {alert['user_id']}\\n")
+            handle.write(f"  - {alert['details']}\\n")
+
+    print(f"Alerts written to {json_path} and {md_path}")
+
+
+def main() -> None:
+    parser = argparse.ArgumentParser(description=__doc__)
+    parser.add_argument("--log-path", default=str(DATA_DIR / "uam_logs.jsonl"))
+    parser.add_argument("--output-dir", default=str(DATA_DIR))
+    args = parser.parse_args()
+
+    config = load_config(CONFIG_PATH)["detection"]
+    hr_records = load_csv(DATA_DIR / "hr_records.csv")
+    assets = load_csv(DATA_DIR / "sensitive_assets.csv")
+    access_requests = load_csv(DATA_DIR / "access_requests.csv")
+    logs = load_logs(Path(args.log_path))
+
+    hr_by_user, assets_by_id, approvals = build_context(hr_records, assets, access_requests)
+    alerts = detect_anomalies(logs, hr_by_user, assets_by_id, approvals, config)
+    write_outputs(alerts, Path(args.output_dir))
+
+
+if __name__ == "__main__":
+    main()
