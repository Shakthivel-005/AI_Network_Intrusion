"""Central configuration: folders, constants and shared vocabulary."""
import os
from pathlib import Path

# Everything the app writes lives in ~/.nids (override with NIDS_HOME)
HOME = Path(os.environ.get("NIDS_HOME", Path.home() / ".nids"))
DATA_DIR = HOME / "data"
MODEL_DIR = HOME / "models"
REPORT_DIR = HOME / "reports"
CAPTURE_DIR = HOME / "captures"
DB_PATH = HOME / "alerts.db"
for _d in (DATA_DIR, MODEL_DIR, REPORT_DIR, CAPTURE_DIR):
    _d.mkdir(parents=True, exist_ok=True)

NORMAL = "Normal"
UNKNOWN_ANOMALY = "Unknown Anomaly"
OTHER_ATTACK = "Other Attack"

SEVERITIES = ["Low", "Medium", "High", "Critical"]
STATUSES = ["New", "Investigating", "Resolved"]
PROTOCOLS = ["TCP", "UDP", "ICMP", "OTHER"]

# Unified schema every dataset is converted to
CORE_COLUMNS = [
    "timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
    "flow_duration", "packet_count", "byte_count", "flow_rate",
]
# Numeric columns used by the "core" model (works for live Zeek/tshark flows too)
CORE_NUMERIC = [
    "flow_duration", "packet_count", "byte_count", "flow_rate",
    "packet_rate", "avg_packet_size", "src_port", "dst_port",
]
