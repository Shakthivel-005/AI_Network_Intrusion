"""Integration with the real SOC tools: Wireshark/tshark, Zeek, Suricata."""
import json
import shutil
import subprocess
import time
from pathlib import Path

import numpy as np
import pandas as pd

from .config import CAPTURE_DIR, PROTOCOLS


def tool_status():
    return {t: shutil.which(t) for t in ("tshark", "dumpcap", "zeek", "suricata", "nmap")}


def list_interfaces():
    p = Path("/sys/class/net")
    return sorted(x.name for x in p.iterdir()) if p.exists() else ["eth0"]


# ------------------------------------------------------------------ capture
def capture(interface="eth0", seconds=30, outfile=None):
    """Capture packets with tshark (needs wireshark group membership or root)."""
    if not shutil.which("tshark"):
        raise RuntimeError("tshark is not installed (sudo apt install tshark).")
    out = Path(outfile or CAPTURE_DIR / f"capture_{time.strftime('%Y%m%d_%H%M%S')}.pcap")
    cmd = ["tshark", "-i", interface, "-a", f"duration:{int(seconds)}", "-F", "pcap", "-w", str(out)]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=int(seconds) + 30)
    if r.returncode != 0 or not out.exists():
        raise RuntimeError(f"Capture failed: {r.stderr.strip()[:400]}\n"
                           "Tip: log out/in after install (wireshark group) or run the app with sudo.")
    return out


def pcap_to_flows(pcap):
    """Aggregate a pcap into bidirectional flows with tshark (no Zeek required)."""
    if not shutil.which("tshark"):
        raise RuntimeError("tshark is not installed (sudo apt install tshark).")
    fields = ["frame.time_epoch", "ip.src", "ip.dst", "ip.proto", "tcp.srcport", "tcp.dstport",
              "udp.srcport", "udp.dstport", "frame.len"]
    cmd = ["tshark", "-r", str(pcap), "-T", "fields", "-E", "separator=,", "-E", "header=y"]
    for f in fields:
        cmd += ["-e", f]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip()[:400])
    from io import StringIO
    p = pd.read_csv(StringIO(r.stdout), low_memory=False)
    p = p.dropna(subset=["ip.src", "ip.dst"])
    if p.empty:
        raise RuntimeError("No IPv4 packets found in the capture.")
    p["sp"] = p["tcp.srcport"].fillna(p["udp.srcport"]).fillna(0).astype(int)
    p["dp"] = p["tcp.dstport"].fillna(p["udp.dstport"]).fillna(0).astype(int)
    p["proto"] = p["ip.proto"].astype(int)
    a = p["ip.src"] + ":" + p["sp"].astype(str)
    b = p["ip.dst"] + ":" + p["dp"].astype(str)
    p["key"] = np.where(a < b, a + "|" + b, b + "|" + a) + "|" + p["proto"].astype(str)
    p = p.sort_values("frame.time_epoch")
    g = p.groupby("key", sort=False).agg(
        t0=("frame.time_epoch", "min"), t1=("frame.time_epoch", "max"),
        packet_count=("frame.len", "size"), byte_count=("frame.len", "sum"),
        src_ip=("ip.src", "first"), dst_ip=("ip.dst", "first"),
        src_port=("sp", "first"), dst_port=("dp", "first"), proto=("proto", "first")).reset_index(drop=True)
    g["timestamp"] = pd.to_datetime(g["t0"], unit="s")
    g["flow_duration"] = (g["t1"] - g["t0"]).clip(lower=0)
    g["flow_rate"] = g["byte_count"] / g["flow_duration"].replace(0, np.nan)
    g["protocol"] = g["proto"].map({1: "ICMP", 6: "TCP", 17: "UDP"}).fillna("OTHER")
    g["protocol_group"] = g["protocol"]
    return g[["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol", "protocol_group",
              "flow_duration", "packet_count", "byte_count", "flow_rate"]]


def _read(x):
    """Accept a file path or the raw text itself."""
    sx = str(x)
    if isinstance(x, Path) or ("\n" not in sx and len(sx) < 500 and Path(sx).exists()):
        return Path(sx).read_text(errors="ignore")
    return sx


# ------------------------------------------------------------------ Zeek
def run_zeek(pcap, outdir=None):
    if not shutil.which("zeek"):
        raise RuntimeError("Zeek is not installed.")
    outdir = Path(outdir or CAPTURE_DIR / f"zeek_{int(time.time())}")
    outdir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["zeek", "-C", "-r", str(Path(pcap).resolve())], cwd=outdir,
                   capture_output=True, text=True, timeout=900, check=False)
    log = outdir / "conn.log"
    if not log.exists():
        raise RuntimeError("Zeek produced no conn.log")
    return log


def parse_zeek_conn(path_or_text):
    """Parse Zeek conn.log (TSV or JSON lines) into the unified flow schema."""
    text = _read(path_or_text)
    lines = [l for l in text.splitlines() if l.strip()]
    if lines and lines[0].startswith("{"):
        d = pd.DataFrame([json.loads(l) for l in lines if l.startswith("{")])
    else:
        fields = next(l.split("\t")[1:] for l in lines if l.startswith("#fields"))
        rows = [l.split("\t") for l in lines if not l.startswith("#")]
        d = pd.DataFrame(rows, columns=fields).replace({"-": np.nan, "(empty)": np.nan})
    num = lambda c: pd.to_numeric(d[c], errors="coerce").fillna(0) if c in d else 0
    out = pd.DataFrame({
        "timestamp": pd.to_datetime(pd.to_numeric(d["ts"], errors="coerce"), unit="s"),
        "src_ip": d["id.orig_h"], "dst_ip": d["id.resp_h"],
        "src_port": pd.to_numeric(d["id.orig_p"], errors="coerce"),
        "dst_port": pd.to_numeric(d["id.resp_p"], errors="coerce"),
        "protocol": d["proto"].astype(str).str.upper(),
        "flow_duration": num("duration"),
        "packet_count": num("orig_pkts") + num("resp_pkts"),
        "byte_count": num("orig_ip_bytes") + num("resp_ip_bytes") if "orig_ip_bytes" in d
        else num("orig_bytes") + num("resp_bytes"),
    })
    out["flow_rate"] = out["byte_count"] / out["flow_duration"].replace(0, np.nan)
    out["protocol_group"] = out["protocol"].where(out["protocol"].isin(PROTOCOLS[:3]), "OTHER")
    return out[out["packet_count"] > 0].reset_index(drop=True)


# ------------------------------------------------------------------ Suricata
def run_suricata(pcap, outdir=None):
    if not shutil.which("suricata"):
        raise RuntimeError("Suricata is not installed (sudo apt install suricata).")
    outdir = Path(outdir or CAPTURE_DIR / f"suricata_{int(time.time())}")
    outdir.mkdir(parents=True, exist_ok=True)
    subprocess.run(["suricata", "-r", str(Path(pcap).resolve()), "-l", str(outdir), "-k", "none"],
                   capture_output=True, text=True, timeout=900, check=False)
    eve = outdir / "eve.json"
    if not eve.exists():
        raise RuntimeError("Suricata produced no eve.json (is the rule set installed? run suricata-update).")
    return eve


SURICATA_SEV = {1: "High", 2: "Medium", 3: "Low"}


def parse_suricata_eve(path_or_text):
    """Convert Suricata eve.json alert events into the project's alert schema."""
    text = _read(path_or_text)
    rows = []
    for line in text.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("event_type") != "alert":
            continue
        a = e.get("alert", {})
        ts = pd.to_datetime(e.get("timestamp"), errors="coerce", utc=True)
        ts = ts.tz_localize(None) if ts is not pd.NaT else ts
        rows.append(dict(
            alert_id="", timestamp=ts, last_seen=ts,
            category=f"Suricata: {a.get('category', 'Alert')}", severity=SURICATA_SEV.get(a.get("severity"), "Medium"),
            confidence=1.0, status="New", analyst_notes="", src_ip=e.get("src_ip"), dst_ip=e.get("dest_ip"),
            flows=1, dst_ports=1, total_bytes=0, description=a.get("signature", ""),
            recommended_action="Validate signature hit in Wireshark; check rule SID "
                               f"{a.get('signature_id', '?')}.", source="Suricata"))
    return pd.DataFrame(rows)
