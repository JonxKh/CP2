
import json
import subprocess
import re
import time
import csv
import os
from collections import defaultdict, deque

import numpy as np
import tensorflow as tf
from pygtail import Pygtail
import requests
import smtplib
import ssl
from email.message import EmailMessage


# ============================================================
# CONFIG
# ============================================================
EVE = "/var/log/suricata/eve.json"
MODEL_PATH = "/opt/iot-ids/Lstm_converted2.tflite"
CSV_LOG = "/var/log/iot_ids_predictions_test.csv"

PROTECTED_HOST = "192.168.0.115"
SAFE_IPS = {"192.168.0.1", PROTECTED_HOST}  

IGNORE_IPV6 = True
BLOCK_ON_SURICATA_ALERT = True

# ---- Block cooldown (NEW) ----
BLOCK_COOLDOWN = 60.0  # 

# ---------------- Heuristic thresholds ----------------
CONN_WINDOW = 10
CONN_THRESHOLD = 40

SYN_WINDOW = 3.0
SYN_THRESHOLD = 200

HTTP_WINDOW = 5.0
HTTP_EVENT_THRESHOLD = 60
HTTP_FLOW_THRESHOLD = 120

PORTSCAN_WINDOW = 10.0
PORTSCAN_UNIQUE_PORTS = 20

# ---------------- ML rule (your request) ----------------
BENIGN_CLASS_IDX = 0
ML_BLOCK_CONF = 0.60       # 60%
ML_BLOCK_HITS = 2          # happens 2 times
ML_BLOCK_WINDOW = 60.0     # within 1 minute

# Notifications (optional)
ADMIN_EMAIL = os.getenv("IDS_ADMIN_EMAIL", "admin@example.com")
SMTP_HOST = os.getenv("IDS_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.getenv("IDS_SMTP_PORT", "587"))
SMTP_USER = os.getenv("IDS_SMTP_USER", "")
SMTP_PASS = os.getenv("IDS_SMTP_PASS", "")

TELEGRAM_BOT_TOKEN = "8475936508:AAFZakRELDnIkFDJiADA7x_37VSH0F7RbnY"
TELEGRAM_CHAT_ID = "6442589424"
ALERT_COOLDOWN = 300

# ✅ Put it here (global constant)
ATTACK_MAP = {
    "Heuristic:SYN_Flood": "SYN Flood",
    "Heuristic:HTTP_Flood": "HTTP Flood",
    "Heuristic:PortScan": "Port Scan",
    "High_Conn_Rate": "Flood / High-rate traffic",
    "ML-Block": "ML Detected Malicious",
    "Suricata-Alert": "Suricata Signature Alert",
}

# ============================================================


# ---------------- helpers ----------------
def is_ipv4(ip: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip or ""))

def get_local_ipv4_addresses():
    ips = set(["127.0.0.1"])
    try:
        out = subprocess.check_output(["ip", "-4", "addr"], text=True)
        for m in re.finditer(r"inet\s+(\d+\.\d+\.\d+\.\d+)/\d+", out):
            ips.add(m.group(1))
    except Exception:
        pass
    return ips

LOCAL_IPS = get_local_ipv4_addresses()
print("[INFO] Local IPv4 addresses:", LOCAL_IPS)


def attacker_from_pair(src, dst):
    """Return the 'other side' IP that is talking to PROTECTED_HOST."""
    if dst == PROTECTED_HOST:
        return src
    if src == PROTECTED_HOST:
        return dst
    return None


# ---------------- nftables ----------------
def ensure_nftables():
    cmds = [
        ["sudo", "nft", "add", "table", "inet", "filter"],
        ["sudo", "nft", "add", "set", "inet", "filter", "bad_ips", "{ type ipv4_addr; timeout 300s; }"],
        ["sudo", "nft", "add", "chain", "inet", "filter", "forward", "{ type filter hook forward priority 0; }"],
        ["sudo", "nft", "add", "chain", "inet", "filter", "input", "{ type filter hook input priority 0; }"],
        ["sudo", "nft", "add", "rule", "inet", "filter", "forward", "ip", "saddr", "@bad_ips", "drop"],
        ["sudo", "nft", "add", "rule", "inet", "filter", "input", "ip", "saddr", "@bad_ips", "drop"],
    ]
    for c in cmds:
        subprocess.run(c, check=False)

def block_ip(ip):
    if not ip or not is_ipv4(ip):
        return
    if ip in SAFE_IPS:
        print(f"[SAFE] Not blocking {ip}")
        return
    subprocess.run(["sudo", "nft", "add", "element", "inet", "filter",
                    "bad_ips", f"{{ {ip} timeout 300s }}"], check=False)
    print(f"❗ Blocked {ip}")

ensure_nftables()


# ---------------- notifications ----------------
_alert_history = {}

def send_email_alert(ip, label, ts):
    if not SMTP_USER or not SMTP_PASS:
        return False
    try:
        msg = EmailMessage()
        human = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        msg["From"] = SMTP_USER
        msg["To"] = ADMIN_EMAIL
        msg["Subject"] = f"IDS Alert: {label} from {ip}"
        msg.set_content(f"⚠️ IDS Alert\nTime: {human}\nIP: {ip}\nEvent: {label}\n\nBlocked by IDS.")
        context = ssl.create_default_context()
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=10) as server:
            server.ehlo()
            server.starttls(context=context)
            server.login(SMTP_USER, SMTP_PASS)
            server.send_message(msg)
        return True
    except Exception as e:
        print(f"[WARN] Email failed: {e}")
        return False

def send_telegram_alert(ip, label, ts, attack_hint=None):
    """
    label: the reason (e.g., 'High_Conn_Rate', 'SYN_Flood', 'ML>=55%x2')
    attack_hint: optional best-guess attack name (e.g., 'SYN Flood', 'HTTP Flood')
    """
    if not TELEGRAM_BOT_TOKEN or not TELEGRAM_CHAT_ID:
        return False
    try:
        human = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))

        possible = attack_hint if attack_hint else "Unknown/Uncertain"
        text = (
            f"⚠️ IDS Alert\n"
            f"Time: {human}\n"
            f"IP: {ip}\n"
            f"Event: Malicious\n"
            f"Possible Attack: {possible}\n"
            f"Trigger: {label}"
        )

        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        r = requests.post(url, json={"chat_id": TELEGRAM_CHAT_ID, "text": text}, timeout=5)
        return r.status_code == 200
    except Exception as e:
        print(f"[WARN] Telegram failed: {e}")
        return False

def notify_admin(ip, label, ts=None, attack_hint=None):
    ts = ts or time.time()
    key = (ip, label)
    if ts - _alert_history.get(key, 0) < ALERT_COOLDOWN:
        return
    _alert_history[key] = ts

    sent = False
    sent |= send_email_alert(ip, label, ts)  # optional: you can also add attack_hint to email similarly
    sent |= send_telegram_alert(ip, label, ts, attack_hint=attack_hint)

    if not sent:
        print(f"[ALERT] {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts))} | {ip} | {label}")


# ---------------- load tflite ----------------
print("=" * 60)
print("Loading TensorFlow Lite model...")
print("=" * 60)
interpreter = tf.lite.Interpreter(model_path=MODEL_PATH)
interpreter.allocate_tensors()
inp = interpreter.get_input_details()[0]
out = interpreter.get_output_details()[0]
print("[INFO] Model input :", inp["shape"], inp["dtype"])
print("[INFO] Model output:", out["shape"], out["dtype"])
print("✅ Model loaded successfully")


# ============================================================
# 24-FEATURE EXTRACTOR (for TCP/UDP flows)
# ============================================================
def extract_features(ev):
    f = ev.get("flow", {}) or {}
    tcp = ev.get("tcp", {}) or {}

    def fnum(obj, key):
        try:
            return float(obj.get(key) or 0.0)
        except Exception:
            return 0.0

    b_ts = fnum(f, "bytes_toserver")
    b_tc = fnum(f, "bytes_toclient")
    p_ts = fnum(f, "pkts_toserver")
    p_tc = fnum(f, "pkts_toclient")
    age  = fnum(f, "age")

    bytes_total = b_ts + b_tc
    pkts_total  = p_ts + p_tc

    eps = 1e-6
    bytes_per_pkt = bytes_total / max(pkts_total, 1.0)
    pkt_rate  = pkts_total / max(age, eps)
    byte_rate = bytes_total / max(age, eps)

    sp = float(ev.get("src_port") or 0.0)
    dp = float(ev.get("dest_port") or 0.0)
    sp_n = sp / 65535.0
    dp_n = dp / 65535.0

    proto = (ev.get("proto") or "").upper()
    is_tcp  = 1.0 if proto == "TCP" else 0.0
    is_udp  = 1.0 if proto == "UDP" else 0.0
    is_icmp = 1.0 if proto == "ICMP" else 0.0

    syn = 1.0 if tcp.get("syn") else 0.0
    ack = 1.0 if tcp.get("ack") else 0.0
    fin = 1.0 if tcp.get("fin") else 0.0
    rst = 1.0 if tcp.get("rst") else 0.0
    psh = 1.0 if tcp.get("psh") else 0.0
    urg = 1.0 if tcp.get("urg") else 0.0

    state = str(f.get("state") or "").lower()
    state_new = 1.0 if state == "new" else 0.0
    alerted = 1.0 if f.get("alerted") is True else 0.0

    app = (ev.get("app_proto") or "").lower()
    app_map = {"dns": 1.0, "http": 2.0, "tls": 3.0, "https": 3.0}
    app_code = app_map.get(app, 0.0)

    if bytes_total == 0.0 and pkts_total == 0.0 and sp == 0.0 and dp == 0.0:
        return None

    feats = np.array([
        b_ts, b_tc, p_ts, p_tc, age,
        bytes_total, pkts_total, bytes_per_pkt, pkt_rate, byte_rate,
        sp_n, dp_n,
        is_tcp, is_udp, is_icmp,
        syn, ack, fin, rst, psh, urg,
        state_new, alerted, app_code
    ], dtype=np.float32)

    return feats.reshape(1, 1, 24)


# ---------------- CSV ----------------
try:
    with open(CSV_LOG, "x") as fh:
        csv.writer(fh).writerow(["ts", "src_ip", "dest_ip", "event_type", "decision", "label", "confidence"])
except FileExistsError:
    pass

def log_csv(ts, src, dst, et, decision, label, conf):
    try:
        with open(CSV_LOG, "a") as fh:
            csv.writer(fh).writerow([ts, src, dst, et, decision, label, f"{conf:.6f}"])
    except Exception:
        pass


# ---------------- state ----------------
recent_conns = defaultdict(lambda: deque())
recent_syn = defaultdict(lambda: deque())
recent_http_evt = defaultdict(lambda: deque())
recent_http_flow = defaultdict(lambda: deque())
recent_ports = defaultdict(lambda: deque())
recent_ml_hits = defaultdict(lambda: deque())  # attacker -> [ts]

blocked_until = {}  # attacker -> ts_until (NEW)

def clear_ip_state(ip):
    recent_conns[ip].clear()
    recent_syn[ip].clear()
    recent_http_evt[ip].clear()
    recent_http_flow[ip].clear()
    recent_ports[ip].clear()
    recent_ml_hits[ip].clear()


def do_block(attacker, reason, now, src, dst, et="flow", conf=1.0):
    """Single place to apply cooldown + block + notify + csv."""
    # cooldown set
    blocked_until[attacker] = now + BLOCK_COOLDOWN
    print(f"🛑 {attacker} → BLOCK ({reason})")
    block_ip(attacker)
    notify_admin(attacker, reason, now)
    log_csv(now, src, dst, et, "BLOCK", "Malicious", conf)
    clear_ip_state(attacker)


# ============================================================
# MAIN LOOP
# ============================================================
print("\n🔎 Monitoring Suricata logs in real time...")

for line in Pygtail(EVE, read_from_end=True, every_n=0.05):
    try:
        ev = json.loads(line)
    except Exception:
        continue

    et = ev.get("event_type", "")
    src = ev.get("src_ip", "")
    dst = ev.get("dest_ip", "")

    if IGNORE_IPV6 and (not is_ipv4(src) or not is_ipv4(dst)):
        continue

    attacker = attacker_from_pair(src, dst)
    if not attacker:
        continue

    if attacker in SAFE_IPS or attacker in LOCAL_IPS:
        continue

    now = time.time()

    # ---- cooldown skip (NEW) ----
    if attacker in blocked_until and now < blocked_until[attacker]:
        continue

    proto = (ev.get("proto") or "").upper()

    # ========================================================
    # BENIGN PRINTING (DNS/HTTP/ICMP) — independent of ML
    # ========================================================
    # 1) Suricata may log ping as event_type == "icmp"
    if et == "icmp" or proto == "ICMP" or "icmp" in ev:
        ic = ev.get("icmp", {}) or {}
        itype = ic.get("type", "")
        icode = ic.get("code", "")
        print(f"✅ {attacker} → Benign (ICMP) type={itype} code={icode}".strip())
        log_csv(now, src, dst, et or "icmp", "ALLOW", "Benign", 1.0)
        # Don't run ML on ICMP
        continue

    # DNS events (often event_type == "dns")
    if et == "dns":
        rn = ((ev.get("dns", {}) or {}).get("rrname")) or ""
        print(f"✅ {attacker} → Benign (DNS) {rn}".strip())
        log_csv(now, src, dst, et, "ALLOW", "Benign", 1.0)
        continue

    # HTTP events (often event_type == "http")
    if et == "http":
        http = ev.get("http", {}) or {}
        host = http.get("hostname", "") or ""
        uri = http.get("url", "") or http.get("uri", "") or ""
        print(f"✅ {attacker} → Benign (HTTP) {host}{uri}".strip())
        log_csv(now, src, dst, et, "ALLOW", "Benign", 1.0)
        # NOTE: we still keep separate HTTP-flood heuristic earlier via event counts
        # but benign printing for normal browsing is here.
        # If you want http flood to still work on event_type http, keep the heuristic below too.
        # We'll NOT continue here if you prefer heuristic to run on http events.
        # For now we continue (benign output) and let flow-based heuristic catch floods.
        continue

    # ---- Suricata alert fast-path ----
    if BLOCK_ON_SURICATA_ALERT and et == "alert":
        do_block(attacker, "Suricata-Alert", now, src, dst, et="alert", conf=1.0)
        continue

    # ---- Portscan heuristic ----
    dport = ev.get("dest_port")
    if isinstance(dport, int):
        dq = recent_ports[attacker]
        while dq and now - dq[0][0] > PORTSCAN_WINDOW:
            dq.popleft()
        dq.append((now, dport))
        uniq = len({p for _, p in dq})
        if uniq >= PORTSCAN_UNIQUE_PORTS:
            do_block(attacker, "PortScan", now, src, dst, et=et or "flow", conf=1.0)
            continue

    # ---- SYN flood heuristic (only meaningful for TCP flows) ----
    if et == "flow" and proto == "TCP":
        f = ev.get("flow", {}) or {}
        tcp = ev.get("tcp", {}) or {}

        pkts_ts = int(f.get("pkts_toserver", 0) or 0)
        pkts_tc = int(f.get("pkts_toclient", 0) or 0)

        syn_flag = bool(tcp.get("syn", False))
        flags = str(tcp.get("tcp_flags", "")).lower()
        flags_ts = str(tcp.get("tcp_flags_ts", "")).lower()
        syn_by_hex = ("02" in flags) or ("02" in flags_ts)

        syn_only = (syn_flag or syn_by_hex) and (pkts_tc == 0) and (pkts_ts >= 1)

        if syn_only:
            dq = recent_syn[attacker]
            while dq and now - dq[0] > SYN_WINDOW:
                dq.popleft()
            dq.append(now)
            if len(dq) >= SYN_THRESHOLD:
                do_block(attacker, "SYN_Flood", now, src, dst, et="flow", conf=1.0)
                continue

    # ---- HTTP flood heuristic (flow stream to 80/8080) ----
    if et == "flow" and proto == "TCP" and int(ev.get("dest_port") or 0) in (80, 8080):
        dq = recent_http_flow[attacker]
        while dq and now - dq[0] > HTTP_WINDOW:
            dq.popleft()
        dq.append(now)
        if len(dq) >= HTTP_FLOW_THRESHOLD:
            do_block(attacker, "HTTP_Flood", now, src, dst, et="flow", conf=1.0)
            continue

    # ---- Connection-rate heuristic (flow only) ----
    if et == "flow":
        dq = recent_conns[attacker]
        while dq and now - dq[0] > CONN_WINDOW:
            dq.popleft()
        dq.append(now)
        if len(dq) >= CONN_THRESHOLD:
            do_block(attacker, "High_Conn_Rate", now, src, dst, et="flow", conf=1.0)
            continue

    # ---- ML inference (flow only, and ONLY TCP/UDP) ----
    if et != "flow":
        continue
    if proto not in ("TCP", "UDP"):
        continue

    x = extract_features(ev)
    if x is None:
        continue

    try:
        interpreter.set_tensor(inp["index"], np.asarray(x, dtype=np.float32))
        interpreter.invoke()
        probs = interpreter.get_tensor(out["index"]).reshape(-1).astype(np.float32)
    except Exception as e:
        print(f"[ERROR] Inference failed: {e}")
        continue

    pred_idx = int(np.argmax(probs))
    pred_conf = float(np.max(probs))
    conf_pct = pred_conf * 100.0
    is_mal = (pred_idx != BENIGN_CLASS_IDX)

    if not is_mal:
        print(f"🔍 {attacker} → Benign  conf={conf_pct:.1f}%")
        log_csv(now, src, dst, "flow", "ALLOW", "Benign", pred_conf)
        recent_ml_hits[attacker].clear()
        continue

    print(f"🔍 {attacker} → Malicious conf={conf_pct:.1f}%")
    log_csv(now, src, dst, "flow", "ALLOW", "Malicious", pred_conf)

    # ---- YOUR ML BLOCK RULE ----
    if pred_conf >= ML_BLOCK_CONF:
        dq = recent_ml_hits[attacker]
        while dq and now - dq[0] > ML_BLOCK_WINDOW:
            dq.popleft()
        dq.append(now)

        if len(dq) >= ML_BLOCK_HITS:
            do_block(attacker, f"ML>={ML_BLOCK_CONF*100:.0f}%x{ML_BLOCK_HITS}", now, src, dst, et="flow", conf=pred_conf)
            continue