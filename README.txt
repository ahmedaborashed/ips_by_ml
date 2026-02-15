IPS BY ML PROJECT
=================

Project Title:
IPS by ML (Intrusion Prevention System using Machine Learning Concepts)

Introduction:
IPS by ML is an advanced cybersecurity project that combines traditional Intrusion Prevention System (IPS)
mechanisms with Machine Learning-inspired concepts to analyze, detect, and respond to suspicious activities in real time.

The system provides intelligent security monitoring on two levels:
- Network Level (Network Interfaces, ARP Spoofing, IP Blocking)
- Browser Level (Malicious URLs, SQL Injection, XSS, Command Injection, etc.)

Unlike traditional IPS systems that rely only on static rule-based detection, IPS by ML applies behavior-based analysis
and scoring logic to evaluate risks dynamically and adapt to modern cyber attack patterns.

----------------------------------------------------------------

Machine Learning Concept in the Project:
Machine Learning plays a conceptual role in this system by enabling intelligent decision-making based on behavior
rather than fixed signatures or trained models.

In this project, ML is applied through:

1. Feature Extraction:
   - Number of active network connections
   - Network traffic volume and changes
   - Interface status (Up / Down)
   - MAC address changes (ARP monitoring)
   - Repeated ARP changes within a time window
   - Browser connection behavior and visited URLs

2. ML-Based Scoring:
   - Each network interface and browser activity is assigned a security score between 0 and 1.
   - Low score (0.0 – 0.4): Normal behavior
   - Medium score (0.4 – 0.6): Suspicious behavior
   - High score (0.6 – 1.0): Potential attack

3. Behavioral Analysis:
   - Sudden traffic spikes increase the risk score.
   - Frequent MAC address changes trigger ARP Spoofing detection.
   - Suspicious URL patterns raise browser security alerts.

4. Decision Logic (Threshold-Based):
   - ML scores are combined with predefined thresholds.
   - The system can automatically:
     * Log security events
     * Raise alerts
     * Block IP addresses
     * Disable network interfaces (Wi-Fi) in severe cases

This hybrid approach makes the system more adaptive and intelligent than traditional rule-based IPS solutions.

----------------------------------------------------------------

Browser Intrusion Prevention System (Browser IPS):
The project includes a Browser IPS implemented as a Chrome Extension that provides real-time protection against web attacks.

Features:
- Detects SQL Injection, XSS, Command Injection, and Path Traversal attempts.
- Uses browser-level blocking rules (DeclarativeNetRequest).
- Automatically blocks malicious URLs.
- Reports detected attacks to the backend server.
- Synchronizes open browser tabs with the dashboard.
- Displays:
  - Active browser connections
  - Remote IP addresses
  - Safe vs Suspicious connections
  - Real-time charts of browser activity

This module helps detect malicious websites and abnormal browsing behavior.

----------------------------------------------------------------

Network Security Features:
- Real-time monitoring of network interfaces
- ARP Spoofing detection using MAC address change analysis
- Automatic Wi-Fi disconnection during severe attacks
- Manual and automatic IP blocking
- Rate-limiting to prevent excessive false positives
- Whitelist support for trusted IPs and MAC addresses
- Alerts logging in a local database

----------------------------------------------------------------

Login System:
The system includes a simple login mechanism to restrict access to the dashboard.

Default Login Credentials:
USERNAME = Net Defenders team  
PASSWORD = delta  

These credentials are required to access the main dashboard and security control panels.

----------------------------------------------------------------

System Architecture:
- Backend: Python (FastAPI)
- Frontend: HTML, CSS, JavaScript
- Visualization: Chart.js
- Database: SQLite (alerts logging)
- Configuration: YAML (config.yaml)
- Network Monitoring: psutil, netifaces
- Browser IPS: Chrome Extension (Manifest V3)
- Security Logic: Behavior-based scoring & threshold rules

----------------------------------------------------------------

Project Structure:
backend/
- main.py        : Core backend logic, IPS engine, APIs, ARP detection, ML scoring

frontend/
- login.html     : Secure login interface
- index.html     : Main dashboard
- network.html   : Network analysis module
- browser.html   : Browser IPS dashboard
- static/        : CSS, JavaScript, images

browser-extension/
- manifest.json  : Chrome extension manifest (v3)
- background.js  : Browser IPS detection and blocking logic

database/
- alerts.db      : SQLite database for security alerts

config.yaml      : System configuration file

----------------------------------------------------------------

How to Run:

1. Backend Setup:
   - Install Python 3.9 or higher.
   - Install dependencies:
     pip install fastapi uvicorn psutil netifaces pyyaml

   - Run the backend server:
     python main.py

   - Open in browser:
     http://127.0.0.1:8000

2. Frontend:
   - Open the web interface through the backend URL.
   - Login using the default credentials.

3. Browser Extension:
   - Open Chrome → Extensions → Enable Developer Mode.
   - Click "Load unpacked".
   - Select the browser-extension folder.
   - The Browser IPS will start monitoring browsing activity automatically.

----------------------------------------------------------------

Developers (Net Defenders Team):
- Ahmed Mohamed Abo Rashed  
- Seif Adel Eltanaihey  
- Mohamed Ahmed Elshanawy  
- Gamal Osama Areda  
- Basmala Mahmoud Radwan  
- Shahd Ehab Mohamed   

----------------------------------------------------------------

Notes:
- Some blocking operations require administrator privileges.
- Dry-Run mode allows safe testing without actual blocking.
- The project is developed for academic and educational purposes.
- The system demonstrates practical usage of Machine Learning concepts in cybersecurity without relying on heavy ML models.
