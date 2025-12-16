# Counterintelligence & Insider Threat Detection Lab

This repository contains materials for a lab on counterintelligence (CI) and insider threat detection. The lab demonstrates how to set up a user-activity monitoring (UAM) program to detect malicious or negligent insider behaviour while respecting privacy and legal constraints.

## Objectives

* **Understand insider threat programs:** Review guidelines from the National Insider Threat Task Force (NITTF) that require monitoring of user activity on classified networks, including keystrokes, application content, screen capture and file shadowing to detect potential insider threats.
* **Install and configure a UAM tool:** Deploy an open-source or demonstration UAM solution in a sandbox environment. Configure it to capture keystrokes, full application content, periodic screen shots and shadow copies of files. Define triggers for specific events (e.g. insertion of removable media, transfer of large amounts of data, access to sensitive files).
* **Integrate contextual data:** Enrich UAM logs with HR records, security clearances, access requests and background check information to give analysts context when investigating anomalies.
* **Develop policies and training:** Draft policies for protecting, interpreting, storing and limiting access to UAM results, and ensure all users sign acknowledgement agreements as required by insider threat directives. Provide training so employees understand monitoring goals and privacy safeguards.
* **Analyze alerts and respond:** Use the collected data to detect anomalous behaviour such as data exfiltration, unusual logins or attempts to bypass security. Simulate escalation paths: initial analyst triage, coordination with CI/HR, investigation and corrective actions.
* **Document and review:** Create an insider threat risk report summarizing detected incidents, mitigation steps and lessons learned. Review UAM configurations and policies regularly to reduce false positives and ensure privacy and civil liberties protections.

This lab uses only publicly available documentation and synthetic data. No actual user data or classified information is required.
