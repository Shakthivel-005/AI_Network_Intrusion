"""Load CIC-IDS2017, CSE-CIC-IDS2018 and UNSW-NB15 CSV files into one unified schema."""
from pathlib import Path
import numpy as np
import pandas as pd

PROTO_NUM = {1: "ICMP", 6: "TCP", 17: "UDP"}

# lower-case, stripped header -> unified name
ALIASES = {
    "timestamp": ["timestamp", "stime", "ts", "start_time", "starttime"],
    "src_ip": ["source ip", "src ip", "srcip", "src_ip", "id.orig_h"],
    "dst_ip": ["destination ip", "dst ip", "dstip", "dst_ip", "id.resp_h"],
    "src_port": ["source port", "src port", "sport", "src_port", "id.orig_p"],
    "dst_port": ["destination port", "dst port", "dsport", "dport", "dst_port", "id.resp_p"],
    "protocol": ["protocol", "proto", "protocol_type"],
    "flow_duration": ["flow duration", "dur", "duration", "flow_duration"],
    "flow_rate": ["flow_rate", "flow bytes/s", "flow byts/s"],
}
FWD_PKTS = ["total fwd packets", "tot fwd pkts", "spkts"]
BWD_PKTS = ["total backward packets", "tot bwd pkts", "dpkts"]
FWD_BYTES = ["total length of fwd packets", "totlen fwd pkts", "sbytes"]
BWD_BYTES = ["total length of bwd packets", "totlen bwd pkts", "dbytes"]
DROP_IDENT = {"flow id", "id", "unnamed: 0", "ltime", "srcip", "dstip"}


def _first(cols, names):
    for n in names:
        if n in cols:
            return n
    return None


def standardize(raw: pd.DataFrame, dayfirst=None):
    """Convert a raw dataset frame into the unified schema. Returns (df, notes)."""
    notes = {}
    df = raw.copy()
    df.columns = [str(c).strip().lower() for c in df.columns]
    df = df.loc[:, ~df.columns.duplicated()]
    cols = set(df.columns)
    out = pd.DataFrame(index=df.index)

    is_cic = "flow duration" in cols
    is_2018 = "tot fwd pkts" in cols
    dur_div = 1e6 if (is_cic or is_2018) else 1.0  # CIC durations are microseconds
    notes["dataset_flavour"] = ("CSE-CIC-IDS2018" if is_2018 else
                                "CIC-IDS2017" if is_cic else "UNSW-NB15 / Zeek-like / generic")

    for target, names in ALIASES.items():
        src = _first(cols, names)
        if src is not None:
            out[target] = df[src]

    # packets / bytes = forward + backward
    fp, bp = _first(cols, FWD_PKTS), _first(cols, BWD_PKTS)
    fb, bb = _first(cols, FWD_BYTES), _first(cols, BWD_BYTES)
    zero = pd.Series(0, index=df.index)
    num = lambda c: pd.to_numeric(df[c], errors="coerce") if c else zero
    out["packet_count"] = df["packet_count"] if "packet_count" in cols else num(fp) + num(bp)
    out["byte_count"] = df["byte_count"] if "byte_count" in cols else num(fb) + num(bb)

    for c in ["src_port", "dst_port", "flow_duration", "packet_count", "byte_count", "flow_rate"]:
        if c in out:
            out[c] = pd.to_numeric(out[c], errors="coerce")
    out["flow_duration"] = out["flow_duration"] / dur_div if "flow_duration" in out else np.nan

    # flow rate (bytes/s): recompute when missing so every dataset has it
    if "flow_rate" not in out:
        out["flow_rate"] = np.nan
    calc = out["byte_count"] / out["flow_duration"].replace(0, np.nan)
    out["flow_rate"] = out["flow_rate"].fillna(calc)

    # protocol -> name
    if "protocol" in out:
        p = out["protocol"]
        n = pd.to_numeric(p, errors="coerce")
        named = p.astype(str).str.upper().str.strip()
        out["protocol"] = np.where(n.notna(), n.map(PROTO_NUM).fillna("OTHER"), named)
    else:
        out["protocol"] = "OTHER"

    # timestamp
    if "timestamp" in out:
        ts = out["timestamp"]
        if pd.api.types.is_numeric_dtype(ts):
            out["timestamp"] = pd.to_datetime(ts, unit="s", errors="coerce")
        else:
            df_first = is_2018 if dayfirst is None else dayfirst
            out["timestamp"] = pd.to_datetime(ts, errors="coerce", dayfirst=df_first)
    if "timestamp" not in out or out["timestamp"].isna().all():
        base = pd.Timestamp.now().floor("s") - pd.Timedelta(seconds=len(out))
        out["timestamp"] = base + pd.to_timedelta(np.arange(len(out)), unit="s")
        notes["timestamp"] = ("Dataset has no timestamps - replay timestamps (1 flow / second) "
                              "were generated so alerts and trends can be shown.")

    for c in ("src_ip", "dst_ip"):
        if c not in out:
            out[c] = "N/A"
            notes[c] = f"{c} not in this CSV (use the TrafficLabelling / full-flow version for IPs)."
        out[c] = out[c].astype(str).str.strip()
    for c in ("src_port", "dst_port"):
        if c not in out:
            out[c] = np.nan

    # label -> raw category text
    cat = None
    if "attack_cat" in cols:
        cat = df["attack_cat"]
        if "label" in cols:  # UNSW: label 0/1 + attack_cat (blank for normal traffic)
            lab = pd.to_numeric(df["label"], errors="coerce")
            blank = cat.isna() | (cat.astype(str).str.strip() == "")
            cat = cat.where(~blank, np.where(lab == 1, "Attack", "Normal"))
    elif "label" in cols:
        cat = df["label"]
        if pd.api.types.is_numeric_dtype(cat):
            cat = np.where(cat == 1, "Attack", "Normal")
    out["label_raw"] = cat if cat is not None else "Normal"
    if cat is None:
        notes["label"] = "No label column found - all rows treated as 'Normal' (unlabelled data)."

    # keep extra numeric columns for the 'extended' feature set
    used = set(sum(ALIASES.values(), []) + FWD_PKTS + BWD_PKTS + FWD_BYTES + BWD_BYTES +
               ["label", "attack_cat", "packet_count", "byte_count"]) | DROP_IDENT
    extra = {}
    for c in df.columns:
        if c in used:
            continue
        s = pd.to_numeric(df[c], errors="coerce")
        if s.notna().mean() > 0.9:
            extra["x_" + "".join(ch if ch.isalnum() else "_" for ch in c).strip("_")] = s
    if extra:
        out = pd.concat([out, pd.DataFrame(extra, index=out.index)], axis=1)
    notes["extra_numeric_features"] = len(extra)
    return out, notes


def load_csv(path, sample_frac=1.0, max_rows=None, seed=42):
    """Read one CSV in chunks so multi-GB files do not exhaust RAM."""
    parts, n = [], 0
    for chunk in pd.read_csv(path, chunksize=200_000, low_memory=False,
                             encoding="latin-1", skipinitialspace=True):
        if sample_frac < 1.0:
            chunk = chunk.sample(frac=sample_frac, random_state=seed)
        parts.append(chunk)
        n += len(chunk)
        if max_rows and n >= max_rows:
            break
    raw = pd.concat(parts, ignore_index=True) if parts else pd.DataFrame()
    if max_rows and len(raw) > max_rows:
        raw = raw.sample(n=max_rows, random_state=seed).reset_index(drop=True)
    return raw


def load_paths(paths, sample_frac=1.0, max_rows=None):
    """Load several CSVs (e.g. all CIC-IDS2017 day files) and unify them."""
    frames, notes = [], {}
    per_file = None if not max_rows else max(1, max_rows // max(1, len(paths)))
    for p in paths:
        raw = load_csv(p, sample_frac=sample_frac, max_rows=per_file)
        if raw.empty:
            continue
        df, nt = standardize(raw)
        df["source_file"] = Path(str(getattr(p, "name", p))).name
        frames.append(df)
        notes.update(nt)
    if not frames:
        raise ValueError("No usable rows were found in the selected files.")
    return pd.concat(frames, ignore_index=True), notes


def find_csvs(folder):
    return sorted(Path(folder).expanduser().rglob("*.csv"))
