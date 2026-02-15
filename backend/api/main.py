from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi import FastAPI, Request, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pathlib import Path
import socket
import subprocess
import netifaces
import platform
import re
from urllib.parse import urlparse, unquote_plus
import math 
try:
    import psutil
except ImportError:
    psutil = None
from starlette.responses import RedirectResponse, FileResponse
from typing import Dict, List, Any, Optional
from datetime import datetime, timedelta

import yaml
import sqlite3
import time
from collections import defaultdict, deque
# ===== Browser IPS Section =====
from pydantic import BaseModel

browser_alerts = []      # تنبيهات البراوزر (RAM)
blocked_domains = set()  # دومينات محظورة
open_sites = {}          # 👈 التابات المفتوحة حاليًا

ATTACK_PATTERNS = {
    "SQL Injection": [
        " or 1=1",
        "or 1=1",
        "' or '1'='1",
        "\" or \"1\"=\"1",
        "union select",
        "--",
        "/*",
        "*/",
        "xp_cmdshell",
        "information_schema",
        "sleep(",
        "benchmark("
    ],
    "XSS": [
        "<script",
        "onerror=",
        "onload=",
        "alert(",
        "%3cscript"
    ],
    "Command Injection": [
        ";",
        "&&",
        "|",
        "`"
    ],
    "Path Traversal": [
        "../",
        "..%2f",
        "%2e%2e%2f"
    ]
}

class BrowserAlert(BaseModel):
    url: str
    issue: str
    severity: str = "Medium"
    timestamp: float | None = None

try:
    with open('config.yaml', 'r', encoding='utf-8') as f:
        config: Dict[str, Any] = yaml.safe_load(f)
except FileNotFoundError:
    print("❌ خطأ: لم يتم العثور على ملف config.yaml. سيتم استخدام الإعدادات الافتراضية (Dry-Run).")
    config = {
        "iface": "eth0",
        "dry_run": True, 
        "auto_block": True, 
        "log_db": "alerts.db",
        "gateway_ip": "192.168.1.1", 
        "whitelist_ips": ["192.168.1.1"],
        "whitelist_macs": [],
        "arp_change_threshold": 3,
        "time_window_seconds": 60,
        "max_auto_blocks_per_minute": 6 
    }
except Exception as e:
    print(f"❌ خطأ أثناء قراءة config.yaml: {e}")
    config = {}

ip_changes: defaultdict[str, deque[tuple[str, float]]] = defaultdict(deque)
blocked_records: Dict[str, Dict[str, Any]] = {}
recent_block_timestamps: deque[float] = deque() 

USERNAME = "Net Defenders team"
PASSWORD = "delta"

app = FastAPI(title="IDPS-ML", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

blocked_interfaces: Dict[str, datetime | None] = {}

FRONTEND_ABS = Path(__file__).parent.parent.parent / "frontend"


def init_db(path: str = config.get('log_db', 'alerts.db')):
    try:
        conn = sqlite3.connect(path)
        c = conn.cursor()

        c.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY,
            time TEXT,
            type TEXT,
            ip TEXT,
            domain TEXT,
            url TEXT, 
            old_mac TEXT,
            new_mac TEXT,
            action TEXT,
            operator TEXT
        )
        """)

        conn.commit()
        conn.close()

    except Exception as e:
        print(f"❌ DB init failed: {e}")

def save_alert_to_db(alert: Dict[str, Any], action: str, operator: str = "System"):
    """تسجيل تنبيه جديد في قاعدة البيانات."""
    db_path = config.get('log_db', 'alerts.db')
    try:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        
        old_mac = alert['changes'][0][0] if alert.get('changes') and alert['changes'] else None
        new_mac = alert['changes'][-1][0] if alert.get('changes') and alert['changes'] else None
        
        c.execute("INSERT INTO alerts (time,type,ip,old_mac,new_mac,action,operator) VALUES (?,?,?,?,?,?,?)",
                  (time.strftime("%Y-%m-%d %H:%M:%S"), alert.get('type'), alert.get('ip'), 
                   old_mac, new_mac, action, operator))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"❌ فشل حفظ السجل في DB: {e}")

def save_browser_alert_to_db(domain: str, ip: str, issue: str, url: str):
    db_path = config.get('log_db', 'alerts.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    c.execute(
        """
        INSERT INTO alerts (time, type, ip, domain, url, action, operator)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
        (
            time.strftime("%Y-%m-%d %H:%M:%S"),
            "Browser Attack",
            ip,
            domain,
            url,           # 👈 هنا اللينك الحقيقي
            issue,
            "Browser IPS"
        )
    )

    conn.commit()
    conn.close()

def disable_wifi_interface():
    """
    يقوم بتعطيل واجهة Wi-Fi على نظام Windows باستخدام netsh.
    اسم الواجهة الافتراضي: 'Wi-Fi' كما يظهر في ipconfig.
    """
    if platform.system() != "Windows":
        print("⚠️ تحذير: فصل Wi-Fi التلقائي مدعوم فقط على Windows في هذا الإعداد.")
        return False
        
    try:
        subprocess.run(
            ['netsh', 'interface', 'set', 'interface', 'Wi-Fi', 'admin=disable'],
            check=True,
            capture_output=True,
            text=True
        )
        print("🚨 Wi-Fi interface disabled due to ARP Spoofing")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ فشل فصل واجهة Wi-Fi: الأمر '{e.cmd}'، الخطأ: {e.stderr.strip()} (قد تحتاج لصلاحيات إدارية).")
        return False
    except Exception as e:
        print("❌ فشل غير متوقع في فصل Wi-Fi:", e)
        return False


def _execute_ip_block_command(ip_address: str, dry_run: bool = True) -> bool:
    """
    حظر IP المستهدف باستخدام netsh (Windows) أو iptables (Linux).
    """
    if not ip_address or not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip_address):
        print("Invalid IP format for blocking:", ip_address)
        return False
    
    if ip_address in config.get('whitelist_ips', []):
        print("Attempt to block whitelisted IP (skipped):", ip_address)
        return False

    system = platform.system()
    
    if dry_run or config.get('dry_run', True):
        print(f"[DRY RUN] ⚠️ كان سيتم حظر IP: {ip_address} على {system}")
        return True

    try:
        if system == "Windows":
            rule_in_name = f"IDPS_Block_In_{ip_address}"
            rule_out_name = f"IDPS_Block_Out_{ip_address}"
            cmd_in = f'netsh advfirewall firewall add rule name="{rule_in_name}" dir=in action=block remoteip={ip_address} enable=yes'
            cmd_out = f'netsh advfirewall firewall add rule name="{rule_out_name}" dir=out action=block remoteip={ip_address} enable=yes'
            
            subprocess.run(cmd_in, shell=True, check=True, capture_output=True, text=True)
            subprocess.run(cmd_out, shell=True, check=True, capture_output=True, text=True)
            print(f"✅ Blocked IP {ip_address} with netsh rules.")
            return True
            
        elif system == "Linux":
            subprocess.run(
                ["sudo", "iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"],
                check=True,
                capture_output=True,
                text=True
            )
            print(f"✅ Blocked IP {ip_address} with iptables.")
            return True
        else:
            print(f"⚠️ تحذير: نظام التشغيل {system} غير مدعوم للحظر التلقائي للـ IP.")
            return False
            
    except subprocess.CalledProcessError as e:
        print("Error running block command:", e.stderr)
        return False
    except Exception as e:
        print("Unexpected error in blocking IP:", e)
        return False

def _execute_ip_unblock_command(ip_address: str, dry_run: bool = True) -> bool:
    """إزالة قواعد حظر IP من جدار الحماية (Windows/Linux)."""
    if not ip_address or not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', ip_address):
        return False
        
    system = platform.system()
    
    if dry_run or config.get('dry_run', True):
        print(f"[DRY RUN] ℹ️ كان سيتم إزالة حظر IP: {ip_address} على {system}")
        return True

    try:
        if system == "Windows":
            rule_in_name = f"IDPS_Block_In_{ip_address}"
            rule_out_name = f"IDPS_Block_Out_{ip_address}"

            cmd_del_in = f'netsh advfirewall firewall delete rule name="{rule_in_name}"'
            cmd_del_out = f'netsh advfirewall firewall delete rule name="{rule_out_name}"'
            
            subprocess.run(cmd_del_in, shell=True, check=False, capture_output=True, text=True)
            subprocess.run(cmd_del_out, shell=True, check=False, capture_output=True, text=True)
            print(f"✅ Unblocked IP {ip_address} (removed netsh rules).")
            return True
            
        elif system == "Linux":
            subprocess.run(
                ["sudo", "iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"],
                check=False, 
                capture_output=True,
                text=True
            )
            print(f"✅ Unblocked IP {ip_address} with iptables.")
            return True
        else:
            return False
            
    except Exception as e:
        print("Unexpected error in unblocking IP:", e)
        return False

def process_arp_change(ip: str, mac: str):
    """
    تطبيق منطق Threshold لاكتشاف ARP Spoofing مع Safety و Rate Limiting.
    """
    
    if (ip in config.get('whitelist_ips', []) or 
        mac.lower() in [m.lower() for m in config.get('whitelist_macs', [])]):
        return 

    now = time.time()
    dq = ip_changes[ip]

    if dq and dq[-1][0].lower() == mac.lower():
        return

    dq.append((mac, now))

    while dq and now - dq[0][1] > config.get('time_window_seconds', 60):
        dq.popleft()

    if len(dq) >= config.get('arp_change_threshold', 3):
        
        gateway_ip = config.get('gateway_ip') 
        if ip == gateway_ip or ip in config.get('whitelist_ips', []):
            print(f"⚠️ Detected change on gateway/whitelisted IP ({ip}) - logging only.")
            save_alert_to_db({"type": "ARP Spoofing", "ip": ip, "changes": list(dq)}, "Detected_on_Whitelisted")
            dq.clear()
            return
            
        max_blocks = config.get('max_auto_blocks_per_minute', 6)
        
        while recent_block_timestamps and now - recent_block_timestamps[0] > 60:
            recent_block_timestamps.popleft()
            
        if len(recent_block_timestamps) >= max_blocks:
            print(f"❌ Auto-block rate limit reached ({max_blocks}/min); skipping auto block for {ip}")
            save_alert_to_db({"type": "ARP Spoofing", "ip": ip, "changes": list(dq)}, "RateLimit_Skip")
            dq.clear()
            return

        alert = {"type": "ARP Spoofing", "ip": ip, "changes": list(dq)}
        
        save_alert_to_db(alert, "ARP_Detected_Auto_Response")
        
        disable_wifi_interface() 
        
        dq.clear()

        if config.get('auto_block', True):
            success = _execute_ip_block_command(ip, dry_run=config.get('dry_run', True))
            action = "AutoBlocked" if success else "AutoBlockFailed"
            if success and not config.get('dry_run', True):
                recent_block_timestamps.append(now)
                blocked_records[ip] = {'mac': mac, 'time': now, 'reason': 'ARP Spoof Auto'}
                save_alert_to_db(alert, action)

def detect_attack(url: str):
    u = url.lower()
    for attack, patterns in ATTACK_PATTERNS.items():
        for p in patterns:
            if p in u:
                return attack
    return None

@app.post("/api/browser/report")
def browser_report(alert: BrowserAlert):
    parsed = urlparse(alert.url)
    full_url = alert.url
    domain = parsed.hostname or alert.url


    try:
        ip = socket.gethostbyname(domain)
    except:
        ip = "Unknown"

    blocked_domains.add(domain)

    browser_alerts.append({
        "url": full_url,  
        "domain": domain, 
        "issue": alert.issue,
        "severity": alert.severity,
        "ip": ip,
        "time": time.strftime("%Y-%m-%d %H:%M:%S")
    })

    save_browser_alert_to_db(
    domain=domain,
    ip=ip,
    issue=alert.issue,
    url=full_url  
)
    return {"status": "blocked"}

@app.get("/api/browser-alerts")
def get_browser_alerts():
    db_path = config.get('log_db', 'alerts.db')
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    c.execute("""
        SELECT time, action, ip, domain, url
        FROM alerts
        WHERE type = 'Browser Attack'
        ORDER BY id DESC
        LIMIT 50
    """)

    alerts = []
    for row in c.fetchall():
        alerts.append({
            "time": row["time"],
            "issue": row["action"],
            "ip": row["ip"],
            "domain": row["domain"],
            "url": row["url"]  
        })

    conn.close()

    return {
        "status": "success",
        "count": len(alerts),
        "alerts": alerts
    }

@app.post("/api/browser/tab-closed")
def browser_tab_closed(data: dict):
    tab_id = data.get("tab_id")
    if tab_id in open_sites:
        del open_sites[tab_id]
    return {"status": "removed"}

@app.post("/api/browser/tabs-sync")
def tabs_sync(data: dict):
    global open_sites

    active_tab_ids = set()
    now_time = time.strftime("%H:%M:%S")
    now_date = time.strftime("%Y-%m-%d")

    for s in data.get("sites", []):
        tab_id = s.get("tab_id")
        url = s.get("url")

        if not tab_id or not url:
            continue

        domain = urlparse(url).hostname
        if not domain:
            continue

        # 🚫 لو الدومين اتحظر قبل كده → تجاهله تمامًا
        if domain in blocked_domains:
            open_sites.pop(tab_id, None)
            continue

        active_tab_ids.add(tab_id)

        try:
            ip = socket.gethostbyname(domain)
        except:
            ip = "Unknown"

        # 🟢 SAFE فقط
        open_sites[tab_id] = {
            "domain": domain,
            "ip": ip,
            "opened_time": open_sites.get(tab_id, {}).get("opened_time", now_time),
            "opened_date": open_sites.get(tab_id, {}).get("opened_date", now_date),
            "status": "Safe"
        }

    # 🧹 شيل أي تاب اتقفل
    closed_tabs = set(open_sites.keys()) - active_tab_ids
    for t in closed_tabs:
        open_sites.pop(t, None)

    return {
        "count": len(open_sites),
        "sites": list(open_sites.values())
    }

@app.get("/api/browser/open-sites")
def get_open_sites():
    return {
        "count": len(open_sites),
        "sites": list(open_sites.values())
    }

@app.on_event("startup")
def _startup():
    print(f"Mounting frontend from: {FRONTEND_ABS}")
    if not FRONTEND_ABS.exists():
        print(f"Warning: Directory {FRONTEND_ABS} does not exist! Please check the path.")
    else:
        app.mount("/static", StaticFiles(directory=str(FRONTEND_ABS)), name="static")
    
    init_db(config.get('log_db', 'alerts.db'))
    
    if config.get('dry_run', True):
         print("ℹ️ وضع التشغيل: **Dry-Run**. لن يتم تنفيذ أوامر الحظر الفعلية للـ IP.")
    else:
         print("🚨 وضع التشغيل: **Active**. سيتم تنفيذ أوامر الحظر الفعلية للـ IP (يتطلب صلاحيات).")


@app.get("/api/get-alerts")
def get_alerts_api():
    """قراءة آخر 50 تنبيه من قاعدة البيانات وعرضها."""
    db_path = config.get('log_db', 'alerts.db')
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        c.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT 50")
        alerts = [dict(row) for row in c.fetchall()]
        conn.close()
        return {"status": "success", "alerts": alerts}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read alerts DB: {e}")

@app.post("/api/unblock-ip/{ip_address}")
def unblock_ip_api(ip_address: str):
    """نقطة نهاية لفك الحظر يدوياً عن IP."""
    success = _execute_ip_unblock_command(ip_address, dry_run=config.get('dry_run', True))
    
    if success:
        if ip_address in blocked_records:
            del blocked_records[ip_address]
        save_alert_to_db({"type": "Manual_Unblock", "ip": ip_address, "changes": []}, "Manual_Unblocked", operator="Admin_UI")
        return {"status": "success", "message": f"Successfully requested unblock for {ip_address}"}
    
    raise HTTPException(status_code=500, detail=f"Failed to execute unblock command for {ip_address}")

@app.post("/api/simulate-arp-change/{ip}/{mac}")
def simulate_arp_change(ip: str, mac: str):
    """محاكاة تغيير في MAC لـ IP معين لغرض الاختبار."""
    process_arp_change(ip, mac)
    return {"status": "simulated", "ip": ip, "mac": mac, "ip_changes_count": len(ip_changes[ip])}


def _execute_block_command(interface_name: str) -> bool:
    """يقوم بتعطيل (Disable) واجهة الشبكة باستخدام أوامر النظام."""
    system = platform.system()
    try:
        if system == "Windows":
            subprocess.run(
                ["netsh", "interface", "set", "interface", 
                 f"name={interface_name}", "admin=disable"], 
                check=True, 
                capture_output=True, 
                text=True
            )
            return True
        elif system == "Linux":
            subprocess.run(
                ["ip", "link", "set", "dev", interface_name, "down"],
                check=True, 
                capture_output=True, 
                text=True
            )
            return True
        else:
            print(f"⚠️ تحذير: نظام التشغيل {system} غير مدعوم للحظر الفعلي.")
            return False
    except subprocess.CalledProcessError as e:
        print(f"❌ فشل حظر الواجهة {interface_name}: الأمر '{e.cmd}'، الخطأ: {e.stderr.strip()}")
        return False
    except FileNotFoundError:
        print(f"❌ فشل حظر الواجهة: لم يتم العثور على أداة إدارة الشبكة في نظام {system}.")
        return False
    except Exception as e:
        print(f"❌ خطأ غير متوقع أثناء حظر الواجهة {interface_name}: {e}")
        return False

def _execute_allow_command(interface_name: str) -> bool:
    """يقوم بتمكين (Enable) واجهة الشبكة باستخدام أوامر النظام."""
    system = platform.system()
    try:
        if system == "Windows":
            subprocess.run(
                ["netsh", "interface", "set", "interface", 
                 f"name={interface_name}", "admin=enable"], 
                check=True, 
                capture_output=True, 
                text=True
            )
            return True
        elif system == "Linux":
            subprocess.run(
                ["ip", "link", "set", "dev", interface_name, "up"],
                check=True, 
                capture_output=True, 
                text=True
            )
            return True
        else:
            return False
    except subprocess.CalledProcessError as e:
        print(f"❌ فشل إلغاء حظر الواجهة {interface_name}: الأمر '{e.cmd}'، الخطأ: {e.stderr.strip()}")
        return False
    except FileNotFoundError:
        print(f"❌ فشل إلغاء حظر الواجهة: لم يتم العثور على أداة إدارة الشبكة في نظام {system}.")
        return False
    except Exception as e:
        print(f"❌ خطأ غير متوقع أثناء إلغاء حظر الواجهة {interface_name}: {e}")
        return False

def _cleanup_expired_blocks():
    """يفحص ويزيل الحظر عن الواجهات التي انتهت صلاحيتها."""
    now = datetime.now()
    interfaces_to_unblock = []
    
    for interface, expiration in blocked_interfaces.items():
        if expiration is not None and expiration <= now:
            interfaces_to_unblock.append(interface)
            
    for interface in interfaces_to_unblock:
        
        allow_success = _execute_allow_command(interface)
        
        if allow_success:
            print(f"✅ تم فك الحظر وتنشيط الواجهة تلقائيًا: {interface} بعد انتهاء المدة.")
        else:
            print(f"⚠️ انتهت مدة حظر الواجهة: {interface}. فشل تنشيط الواجهة تلقائيًا على مستوى النظام (قد تحتاج لصلاحيات إدارية/Root).")
        
        if interface in blocked_interfaces:
            del blocked_interfaces[interface]


@app.get("/", response_class=HTMLResponse)
def login_page():
    login_path = FRONTEND_ABS / "login.html"
    if login_path.exists():
        return HTMLResponse(content=login_path.read_text(encoding="utf-8"))
    return HTMLResponse(content="<h1>⚠️ ملف login.html غير موجود في مجلد frontend</h1>", status_code=404)


@app.post("/login", response_class=HTMLResponse)
def login(username: str = Form(...), password: str = Form(...)):
    if username == USERNAME and password == PASSWORD:
        return RedirectResponse(url="/static/index.html", status_code=303)
    else:
        error_message_html = '<p class="error">اسم المستخدم أو كلمة المرور غير صحيحة</p>'
        
        login_html = (FRONTEND_ABS / "login.html").read_text(encoding="utf-8")
        
        form_end_tag = "</form>"
        if form_end_tag in login_html:
             login_html_with_error = login_html.replace(form_end_tag, f"{form_end_tag}{error_message_html}")
             return HTMLResponse(content=login_html_with_error)

        return HTMLResponse(content=login_html) 

@app.post("/api/login")
async def login_api(username: str = Form(...), password: str = Form(...)):
    if username == USERNAME and password == PASSWORD:
        return {"status": "success", "redirect_url": "/static/index.html"}
    else:
        raise HTTPException(status_code=401, detail="Invalid credentials")

def _get_mac_from_os(nic_name):
    if platform.system() == "Windows":
        try:
            raw = subprocess.check_output("ipconfig /all", shell=True, text=True, errors='ignore').split('\n')
            
            mac_map = {}
            current_nic_description = None 
            
            for line in raw:
                nic_match = re.match(r'^\s*([^\n\r:]+):\s*$', line)
                if nic_match:
                    current_nic_description = nic_match.group(1).strip()
                    continue

                mac_match = re.search(r'[\w\s.-]+:[\s]*([\w]{2}(?:[-\s:])[\w]{2}(?:[-\s:])[\w]{2}(?:[-\s:])[\w]{2}(?:[-\s:])[\w]{2}(?:[-\s:])[\w]{2})', line, re.IGNORECASE)
                if mac_match and current_nic_description:
                    mac_address = re.sub(r'[-\s]', ':', mac_match.group(1)) 
                    mac_map[current_nic_description] = mac_address
                    continue
            
            for ipconfig_name, mac in mac_map.items():
                if nic_name.lower() in ipconfig_name.lower() or ipconfig_name.lower() in nic_name.lower():
                    return mac
                
            return None 
            
        except Exception as e:
             return None
    return None

def _get_interfaces():
    
    _cleanup_expired_blocks()
    
    out = []
    
    discovered_interfaces = set() 
    
    ML_SCORE_PLACEHOLDER = 0.00 
    
    HIGH_TRAFFIC_MB = 0.5 
    LOW_TRAFFIC_MB = 0.1  
    
    if psutil:
        for nic, addrs in psutil.net_if_addrs().items():
            discovered_interfaces.add(nic) 
            
            stats = psutil.net_if_stats().get(nic)
            is_up = stats.isup if stats else False
            io_counters = psutil.net_io_counters(pernic=True).get(nic)
            bytes_sent = io_counters.bytes_sent if io_counters else 0
            bytes_recv = io_counters.bytes_recv if io_counters else 0
            
            nic_name_lower = nic.lower()
            if "ethernet" in nic_name_lower or "eth" in nic_name_lower:
                protocol = "TCP/UDP (Ethernet)"
            elif "wi-fi" in nic_name_lower or "wlan" in nic_name_lower:
                protocol = "TCP/UDP (Wireless)"
            elif "loopback" in nic_name_lower:
                protocol = "Loopback (TCP/IP)"
            else:
                protocol = "TCP/UDP" 
            
            total_bytes_mb = (bytes_sent + bytes_recv) / (1024 * 1024)
            
            ml_score = min(total_bytes_mb / 0.5, 1.0) 
            
            ml_score = max(0.0, round(ml_score, 2)) 
            
            if not is_up:
                severity = "Low" 
            elif total_bytes_mb >= HIGH_TRAFFIC_MB:
                severity = "High"    
            elif total_bytes_mb >= LOW_TRAFFIC_MB:
                severity = "Medium"  
            else:
                severity = "Low"     
                
            if severity == "High":
                mac_status = "Recommended"
            else:
                mac_status = "Unknown"

            is_blocked = nic in blocked_interfaces and (blocked_interfaces[nic] is None or blocked_interfaces[nic] > datetime.now())
            
            entry = {
                "interface": nic,
                "is_up": is_up,
                "protocol": protocol,
                "ml_score": ml_score,
                "severity": severity,
                "mac_status": mac_status, 
                "is_blocked": is_blocked
            }
            
            mac_address = None
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    entry["ipv4"] = addr.address
                    entry["netmask"] = addr.netmask
                elif addr.family == socket.AF_INET6:
                    entry["ipv6"] = addr.address
                elif addr.family == socket.AF_LINK:
                    mac_address = addr.address 
            
            if not mac_address or mac_address == "00:00:00:00:00:00":
                mac_address = _get_mac_from_os(nic)
            
            if mac_address:
                entry["mac"] = mac_address.upper()
            
            if "ipv4" in entry or "ipv6" in entry or "mac" in entry or is_blocked:
                out.append(entry)
                
    else:
        for nic in netifaces.interfaces():
            discovered_interfaces.add(nic)
            
            ml_score = 0.0 
            severity = "Medium" 
            mac_status = "Unknown"
            protocol = "TCP/UDP" 
            
            is_blocked = nic in blocked_interfaces and (blocked_interfaces[nic] is None or blocked_interfaces[nic] > datetime.now())

            entry = {
                "interface": nic,
                "is_up": True, 
                "protocol": protocol,
                "ml_score": ml_score,
                "severity": severity,
                "mac_status": mac_status, 
                "is_blocked": is_blocked
            }
            addrs = netifaces.ifaddresses(nic)
            mac_address = None
            
            if netifaces.AF_INET in addrs:
                ipv4 = addrs[netifaces.AF_INET][0]
                entry["ipv4"] = ipv4.get("addr", "")
                entry["netmask"] = ipv4.get("netmask", "")
            if netifaces.AF_INET6 in addrs:
                entry["ipv6"] = addrs[netifaces.AF_INET6][0].get("addr", "")
            if netifaces.AF_LINK in addrs:
                mac_address = addrs[netifaces.AF_LINK][0].get("addr", "")
            
            if not mac_address or mac_address == "00:00:00:00:00:00":
                mac_address = _get_mac_from_os(nic)
                
            if mac_address:
                entry["mac"] = mac_address.upper()
            
            if "ipv4" in entry or "ipv6" in entry or "mac" in entry or is_blocked:
                out.append(entry)

    for nic in blocked_interfaces:
        is_blocked_now = blocked_interfaces[nic] is None or blocked_interfaces[nic] > datetime.now()
        
        if nic not in discovered_interfaces and is_blocked_now:
            out.append({
                "interface": nic,
                "is_up": False,
                "protocol": "N/A (Blocked)",
                "ml_score": 0.0,
                "severity": "Low", 
                "mac_status": "Unknown",
                "is_blocked": True,
                "ipv4": "-",
                "ipv6": "-",
            })
            
    return out

def _get_gateway_dns_ssid():
    gw = ""
    dns = []
    ssid = ""
    try:
        if netifaces:
            gws = netifaces.gateways()
            default = gws.get('default', {})
            gwinfo = default.get(netifaces.AF_INET)
            if gwinfo:
                gw = gwinfo[0]
                config['gateway_ip'] = gw 
    except Exception:
        pass
    try:
        raw = subprocess.check_output("ipconfig /all", shell=True, text=True, errors='ignore')
        collect = False
        for line in raw.splitlines():
            line = line.strip()
            if line.lower().startswith("dns servers"):
                parts = line.split(":", 1)
                if len(parts) == 2 and parts[1].strip():
                    dns_entry = parts[1].strip()
                    if dns_entry:
                        dns.append(dns_entry)
                collect = True
                continue
            if collect:
                if line == "" or ':' in line:
                    collect = False
                elif re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', line.strip()):
                    dns.append(line.strip())
                elif re.match(r'^[\da-fA-F:]+$', line.strip()):
                     dns.append(line.strip())
    except Exception:
        pass
    try:
        out = subprocess.check_output("netsh wlan show interfaces", shell=True, text=True, errors='ignore')
        for line in out.splitlines():
            if "SSID" in line and "BSSID" not in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    ssid_val = parts[1].strip()
                    if ssid_val.startswith('"') and ssid_val.endswith('"'):
                         ssid = ssid_val[1:-1]
                    else:
                         ssid = ssid_val
                    break
    except Exception:
        pass
    return {"gateway": gw, "dns": dns, "ssid": ssid}

@app.get("/api/network-info")
def api_network_info():
    net = {"interfaces": _get_interfaces()}
    net.update(_get_gateway_dns_ssid())
    net["hostname"] = socket.gethostname()
    
    if not net.get("ssid") or net["ssid"].lower() in ["", "not applicable", "غير متوفر"]:
        net["ssid"] = None 

    return {"network": net}

@app.post("/api/block/{interface}/{duration}")
def block_interface(interface: str, duration: str):
    durations = {"minute": 1, "hour": 60, "day": 1440, "permanent": None}
    
    if duration == "custom":
        return {"status": "custom_duration_required"}
        
    minutes = durations.get(duration)

    if not _execute_block_command(interface):
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to execute block command for {interface}. (Requires Administrator/root privileges)"
        )
    
    if minutes is not None:
        expiration = datetime.now() + timedelta(minutes=minutes)
        blocked_interfaces[interface] = expiration
    elif duration == "permanent":
        blocked_interfaces[interface] = None
        expiration = None
    else:
        _execute_allow_command(interface) 
        raise HTTPException(status_code=400, detail="Invalid duration specified.")
        
    return {"status": "blocked", "interface": interface, "expires": str(expiration) if expiration else "Permanent"}

@app.post("/api/block-custom/{interface}/{minutes}")
def block_interface_custom(interface: str, minutes: int):
    
    if not _execute_block_command(interface):
        raise HTTPException(
            status_code=500, 
            detail=f"Failed to execute block command for {interface}. (Requires Administrator/root privileges)"
        )
        
    if minutes <= 0:
        expiration = None
        blocked_interfaces[interface] = None
        expires_str = "Permanent"
    else:
        expiration = datetime.now() + timedelta(minutes=minutes)
        blocked_interfaces[interface] = expiration
        expires_str = str(expiration)
        
    return {"status": "blocked", "interface": interface, "expires": expires_str}


@app.post("/api/allow/{interface}")
def allow_interface(interface: str):
    
    if not _execute_allow_command(interface):
         raise HTTPException(
            status_code=500, 
            detail=f"Failed to execute allow command for {interface}. (Requires Administrator/root privileges)"
        )
        
    if interface in blocked_interfaces:
        del blocked_interfaces[interface]
    return {"status": "allowed", "interface": interface}

@app.delete("/api/delete/{interface}")
def delete_interface(interface: str):
    if interface in blocked_interfaces:
        del blocked_interfaces[interface]
    return {"status": "deleted", "interface": interface}