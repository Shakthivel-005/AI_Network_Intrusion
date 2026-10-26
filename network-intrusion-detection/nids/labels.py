"""Label cleaning: fixes inconsistent / corrupted label strings across datasets."""
import re
import pandas as pd
from .config import NORMAL

_NORMAL_WORDS = {"benign", "normal", "-", "0", "", "nan", "none", "legitimate"}
_ALIASES = {"backdoors": "Backdoor", "port scan": "PortScan", "portscan": "PortScan"}


def normalize_label(x) -> str:
    """'BENIGN' -> 'Normal'; 'Web Attack <garbage> Brute Force' -> 'Web Attack - Brute Force'."""
    if x is None or (isinstance(x, float) and pd.isna(x)):
        return NORMAL
    s = str(x)
    s = re.sub(r"\s*[^\x20-\x7e]+\s*", " - ", s)  # corrupted dash / encoding garbage
    s = re.sub(r"\s+", " ", s).strip()
    low = s.lower()
    if low in _NORMAL_WORDS:
        return NORMAL
    return _ALIASES.get(low, s)


def to_family(cat: str) -> str:
    """Group sub-types into families (DoS Hulk / GoldenEye / slowloris -> DoS)."""
    low = cat.lower()
    if cat == NORMAL:
        return NORMAL
    if low.startswith("ddos"):
        return "DDoS"
    if low.startswith("dos"):
        return "DoS"
    if "web attack" in low or "sql" in low or "xss" in low:
        return "Web Attack"
    if "patator" in low or "brute" in low:
        return "Brute Force"
    if "portscan" in low or "port scan" in low:
        return "Port Scan"
    if low.startswith("bot"):
        return "Bot"
    return cat
