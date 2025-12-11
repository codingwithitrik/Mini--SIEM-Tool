import win32evtlog  # For Windows event logs
import sqlite3
import time
import smtplib
from email.mime.text import MIMEText
import requests
import threading
from flask import Flask, render_template, jsonify
import matplotlib.pyplot as plt
import io
import base64

# Configuration
DB_PATH = 'mini_siem.db'
ALERT_EMAIL = 'your_email@gmail.com'  # Replace with your email
EMAIL_PASSWORD = 'your_password'  # Use app password for Gmail
TELEGRAM_BOT_TOKEN = 'your_bot_token'  # From BotFather
TELEGRAM_CHAT_ID = 'your_chat_id'  # Your Telegram chat ID
ALERT_METHOD = 'telegram'  # 'email' or 'telegram'

# Initialize Flask app
app = Flask(__name__)

# Database setup
def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT,
                    source TEXT,
                    event_id INTEGER,
                    message TEXT,
                    severity TEXT)''')
    c.execute('''CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY,
                    timestamp TEXT,
                    rule TEXT,
                    details TEXT)''')
    conn.commit()
    conn.close()

# Collect Windows logs
def collect_logs():
    sources = ['System', 'Security', 'Application']  # Add 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall' for firewall
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    for source in sources:
        try:
            log = win32evtlog.OpenEventLog(None, source)
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(log, flags, 0)
            for event in events:
                timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(event.TimeGenerated))
                severity = 'Info' if event.EventType == 4 else 'Warning' if event.EventType == 2 else 'Error'
                c.execute('INSERT INTO logs (timestamp, source, event_id, message, severity) VALUES (?, ?, ?, ?, ?)',
                          (timestamp, source, event.EventID, str(event.StringInserts), severity))
        except Exception as e:
            print(f"Error collecting {source} logs: {e}")
    conn.commit()
    conn.close()

# Detection rules
def detect_anomalies():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    # Brute force: Multiple failed logins (Event ID 4625)
    c.execute("SELECT COUNT(*) FROM logs WHERE event_id=4625 AND timestamp > datetime('now', '-5 minutes')")
    if c.fetchone()[0] > 5:
        alert('Brute Force Attempt', 'Multiple failed login attempts detected.')
    
    # Unexpected admin login (Event ID 4672, check for unusual details)
    c.execute("SELECT message FROM logs WHERE event_id=4672 ORDER BY timestamp DESC LIMIT 1")
    last_admin = c.fetchone()
    if last_admin and 'unusual_ip' in last_admin[0]:  # Placeholder: Add IP checking logic
        alert('Unexpected Admin Login', 'Admin login from unusual location.')
    
    # Disabled antivirus (Event ID for service stop, e.g., 7036 for Windows Defender)
    c.execute("SELECT message FROM logs WHERE event_id=7036 AND message LIKE '%Windows Defender%' ORDER BY timestamp DESC LIMIT 1")
    if c.fetchone():
        alert('Antivirus Disabled', 'Antivirus service stopped.')
    
    # Firewall port scan (Rapid connections, Event ID 5152)
    c.execute("SELECT COUNT(*) FROM logs WHERE event_id=5152 AND timestamp > datetime('now', '-1 minute')")
    if c.fetchone()[0] > 10:
        alert('Port Scan Detected', 'Possible port scanning activity.')
    
    # USB insertion (Event ID 20001 or similar from System)
    c.execute("SELECT message FROM logs WHERE event_id=20001 AND message LIKE '%USB%' ORDER BY timestamp DESC LIMIT 1")
    if c.fetchone():
        alert('USB Device Inserted', 'New USB device detected.')
    
    # Large file transfer (Placeholder: Monitor file sizes if logs include them)
    # Add custom logic based on your logs
    
    conn.close()

# Send alerts
def alert(rule, details):
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('INSERT INTO alerts (timestamp, rule, details) VALUES (?, ?, ?)', (timestamp, rule, details))
    conn.commit()
    conn.close()
    
    message = f"Alert: {rule}\nDetails: {details}\nTime: {timestamp}"
    if ALERT_METHOD == 'email':
        msg = MIMEText(message)
        msg['Subject'] = f'Mini-SIEM Alert: {rule}'
        msg['From'] = ALERT_EMAIL
        msg['To'] = ALERT_EMAIL
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(ALERT_EMAIL, EMAIL_PASSWORD)
        server.sendmail(ALERT_EMAIL, ALERT_EMAIL, msg.as_string())
        server.quit()
    elif ALERT_METHOD == 'telegram':
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        requests.post(url, data={'chat_id': TELEGRAM_CHAT_ID, 'text': message})

# Flask routes
@app.route('/')
def dashboard():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 50")
    logs = c.fetchall()
    c.execute("SELECT * FROM alerts ORDER BY timestamp DESC LIMIT 10")
    alerts = c.fetchall()
    conn.close()
    
    # Simple chart: Alerts over time (last 24 hours)
    plt.figure(figsize=(6, 4))
    # Placeholder: Add real data plotting
    plt.title('Alerts in Last 24 Hours')
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    chart = base64.b64encode(buf.read()).decode('utf-8')
    buf.close()
    
    return render_template('dashboard.html', logs=logs, alerts=alerts, chart=chart)

@app.route('/api/logs')
def api_logs():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("SELECT * FROM logs ORDER BY timestamp DESC LIMIT 100")
    logs = c.fetchall()
    conn.close()
    return jsonify(logs)

# Main loop
def monitor():
    init_db()
    while True:
        collect_logs()
        detect_anomalies()
        time.sleep(60)  # Check every minute

# Run monitoring in a thread
threading.Thread(target=monitor, daemon=True).start()

if __name__ == '__main__':
    app.run(debug=True)
