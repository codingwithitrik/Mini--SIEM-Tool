Log Monitoring & Alerting System (Mini-SIEM) in Python
This is a lightweight, open-source Mini-SIEM tool designed for small businesses. It collects logs from Windows Event Viewer (including system, security, and application logs), firewall (via Windows Firewall logs), and VPN (simulated or from event logs). It uses SQLite for storage, detects predefined suspicious activities, sends real-time alerts via email or Telegram, and provides a simple Flask dashboard for viewing logs and alerts.

Key Features
Log Collection: Reads Windows event logs using pywin32. Firewall logs are parsed from Windows Firewall event logs. VPN logs are simulated (extend to readfrom actual VPN software like OpenVPN logs).
Detection Rules:
Brute force login attempts (multiple failed logins).
Unexpected admin login (logins from unusual IPs or times).
Disabled antivirus (events indicating antivirus service stopped).
Firewall port scan detection (rapid connection attempts to multiple ports).
USB device insertion (from system logs).
Large file transfer alerts (monitor file sizes in logs, if available).
Alerts: Email via SMTP or Telegram via bot API.
Dashboard: Flask web app showing recent logs, alerts, and a simple chart (using Matplotlib for visualization).
Storage: SQLite database for logs and alerts.
Tech Stack: Python, SQLite, Flask, pywin32 (for Windows logs), smtplib/requests (for alerts).
