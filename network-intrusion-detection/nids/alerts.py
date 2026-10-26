"""Module 4 - turn model output into SOC alerts (grouped to fight alert fatigue) + SQLite store."""
import sqlite3
import numpy as np
import pandas as pd

from .config import DB_PATH, SEVERITIES, UNKNOWN_ANOMALY

BASE_SEVERITY = [  # (keyword, severity) - first match wins
    ("bot", "Critical"), ("infiltration", "Critical"), ("heartbleed", "Critical"),
    ("backdoor", "Critical"), ("worm", "Critical"), ("shellcode", "High"), ("exploit", "High"),
    ("ddos", "Critical"), ("dos", "High"), ("brute", "High"), ("web attack", "High"),
    ("sql", "Critical"), ("port scan", "Medium"), ("portscan", "Medium"), ("recon", "Medium"),
    ("fuzz", "Medium"), ("generic", "Medium"), ("analysis", "Low"),
    (UNKNOWN_ANOMALY.lower(), "Medium"), ("other attack", "Medium"),
]

PLAYBOOK = {
    "DoS": ("Single source exhausting a service with many short, high-rate flows.",
            "Rate-limit or block the source IP at the firewall; check web server load; enable SYN cookies."),
    "DDoS": ("Many distributed sources hitting one service at the same time.",
             "Engage upstream/CDN DDoS protection; enable rate limiting; preserve logs for escalation."),
    "Port Scan": ("One host probing many ports - reconnaissance before an attack.",
                  "Block/monitor the scanner; review exposed services; check if any follow-up traffic exists."),
    "Brute Force": ("Repeated login attempts against SSH/FTP.",
                    "Block the source; enforce key-only SSH + fail2ban; reset targeted credentials."),
    "Web Attack": ("Application-layer attack (login brute force / injection) on the web server.",
                   "Review web server logs and WAF; patch the app; block the source."),
    "Bot": ("Periodic low-volume traffic to an external host - possible botnet beaconing.",
            "Isolate the internal host; capture memory/disk; hunt for the C2 address in other logs."),
    UNKNOWN_ANOMALY: ("Traffic unlike anything seen in normal training data (no known attack class).",
                      "Manually review the flows in Wireshark; compare against baseline; escalate if confirmed."),
}
DEFAULT_PLAY = ("Suspicious traffic matching a known attack class.",
                "Review the flows, confirm the source, and contain the host if malicious.")


def playbook(category):
    for k, v in PLAYBOOK.items():
        if k.lower() == str(category).lower():
            return v
    return DEFAULT_PLAY


def base_severity(category):
    low = str(category).lower()
    for kw, sev in BASE_SEVERITY:
        if kw in low:
            return sev
    return "Medium"


def compute_severity(category, confidence, flows=1, repeat_offender=False):
    """Base severity by attack type, adjusted by confidence, volume and repeat behaviour."""
    lvl = SEVERITIES.index(base_severity(category))
    if confidence < 0.60:
        lvl -= 1
    if flows >= 200 or repeat_offender:
        lvl += 1
    return SEVERITIES[int(np.clip(lvl, 0, len(SEVERITIES) - 1))]


def build_alerts(scored: pd.DataFrame, window="10min", min_conf=0.5):
    """Group flagged flows by (source IP, category, time window) into incident-level alerts."""
    f = scored[(scored["final_category"] != "Normal") & (scored["final_conf"] >= min_conf)].copy()
    cols = ["alert_id", "timestamp", "last_seen", "category", "severity", "confidence", "status",
            "analyst_notes", "src_ip", "dst_ip", "flows", "dst_ports", "total_bytes",
            "description", "recommended_action", "source"]
    if f.empty:
        return pd.DataFrame(columns=cols)
    f["src_ip"] = f["src_ip"].fillna("unknown").astype(str)
    f["bucket"] = f["timestamp"].dt.floor(window)
    # distributed attacks (DDoS) are ONE incident, not one alert per bot
    f["grp"] = np.where(f["final_category"].str.lower().str.startswith("ddos"), "(distributed)", f["src_ip"])
    mode = lambda s: s.mode().iloc[0] if not s.mode().empty else ""
    g = f.groupby(["grp", "final_category", "bucket"], sort=False).agg(
        timestamp=("timestamp", "min"), last_seen=("timestamp", "max"),
        confidence=("final_conf", "mean"), flows=("final_conf", "size"),
        n_src=("src_ip", "nunique"), dst_ip=("dst_ip", mode),
        dst_ports=("dst_port", "nunique"), total_bytes=("byte_count", "sum")).reset_index()
    g = g.rename(columns={"final_category": "category", "grp": "src_ip"})
    g.loc[g["src_ip"] == "(distributed)", "src_ip"] = g["n_src"].map(lambda n: f"{n} distributed sources")
    counts = g.groupby("src_ip")["category"].transform("size")
    g["severity"] = [compute_severity(c, cf, fl, rep >= 6 and fl >= 10) for c, cf, fl, rep in
                     zip(g["category"], g["confidence"], g["flows"], counts)]
    g["confidence"] = g["confidence"].round(3)
    g["status"], g["analyst_notes"], g["source"] = "New", "", "ML"
    g["description"] = g["category"].map(lambda c: playbook(c)[0])
    g["recommended_action"] = g["category"].map(lambda c: playbook(c)[1])
    g["alert_id"] = ""
    return g.sort_values("timestamp").reset_index(drop=True)[cols]


# --------------------------------------------------------------------- SQLite
def _conn():
    return sqlite3.connect(DB_PATH)


def _next_id():
    try:
        with _conn() as c:
            ids = pd.read_sql("SELECT alert_id FROM alerts", c)["alert_id"]
        nums = ids.str.replace("ALT-", "", regex=False).astype(int)
        return int(nums.max()) + 1 if len(nums) else 1001
    except Exception:
        return 1001


def save_alerts(df: pd.DataFrame, replace_source=None):
    """Assign IDs (ALT-1001, ALT-1002 ...) and persist. replace_source='ML' wipes old ML alerts first."""
    df = df.copy()
    if replace_source:
        try:
            with _conn() as c:
                c.execute("DELETE FROM alerts WHERE source = ?", (replace_source,))
        except sqlite3.OperationalError:
            pass
    start = _next_id()
    df["alert_id"] = [f"ALT-{start + i}" for i in range(len(df))]
    out = df.copy()
    for c in ("timestamp", "last_seen"):
        out[c] = pd.to_datetime(out[c]).dt.strftime("%Y-%m-%d %H:%M:%S")
    with _conn() as c:
        out.to_sql("alerts", c, if_exists="append", index=False)
    return df


def load_alerts():
    try:
        with _conn() as c:
            df = pd.read_sql("SELECT * FROM alerts", c)
    except Exception:
        return pd.DataFrame()
    for c in ("timestamp", "last_seen"):
        df[c] = pd.to_datetime(df[c], errors="coerce")
    return df.sort_values("timestamp").reset_index(drop=True)


def update_alerts(edited: pd.DataFrame):
    rows = [(r.status, r.analyst_notes if isinstance(r.analyst_notes, str) else "", r.alert_id)
            for r in edited.itertuples()]
    with _conn() as c:
        c.executemany("UPDATE alerts SET status=?, analyst_notes=? WHERE alert_id=?", rows)
    return len(rows)


def clear_alerts():
    with _conn() as c:
        c.execute("DROP TABLE IF EXISTS alerts")
