"""Realistic synthetic flow generator so the project works before you download the big datasets.

It imitates CIC-IDS2017-style flows (normal browsing/DNS/SSH + DoS, DDoS, port scans,
brute force, web attacks and botnet beacons) and deliberately injects dirty data
(duplicates, inf, NaN, negative values, corrupted labels) for the cleaning module.
Attacker addresses use RFC 5737 documentation ranges, so they are not real hosts.
"""
import numpy as np
import pandas as pd

PROFILE = {  # name -> share of traffic
    "BENIGN": 0.72, "DoS Hulk": 0.06, "DDoS": 0.06, "PortScan": 0.07,
    "SSH-Patator": 0.035, "FTP-Patator": 0.015,
    "Web Attack \ufffd Brute Force": 0.02, "Bot": 0.02,
}
SERVERS = {"web": "192.168.10.50", "ssh": "192.168.10.20", "ftp": "192.168.10.21", "dns": "192.168.10.3"}


def _lognorm(rng, mu, sigma, n):
    return rng.lognormal(mu, sigma, n)


def _make(rng, kind, n, t0, t1):
    ts = t0 + (t1 - t0) * rng.random(n)
    clients = np.array([f"192.168.10.{i}" for i in range(100, 160)])
    ext_pool = np.array([f"203.0.113.{i}" for i in range(2, 250)])
    d = {}
    if kind == "BENIGN":
        hour = rng.normal(13, 4, n) % 24  # daytime heavy
        ts = t0 + (hour / 24.0) * (t1 - t0) * 0 + (t1 - t0) * (hour / 24.0)
        proto = rng.choice(["TCP", "UDP", "ICMP"], n, p=[0.70, 0.28, 0.02])
        dport = rng.choice([80, 443, 53, 22, 25, 123, 445, 3389, 8080], n,
                           p=[0.22, 0.38, 0.2, 0.04, 0.02, 0.04, 0.03, 0.02, 0.05])
        dport = np.where(proto == "ICMP", 0, dport)
        pk = 1 + rng.poisson(_lognorm(rng, 1.6, 1.0, n))
        d.update(src_ip=rng.choice(clients, n), dst_ip=rng.choice(list(SERVERS.values()) + ["8.8.8.8", "1.1.1.1"], n),
                 src_port=rng.integers(1024, 65535, n), dst_port=dport, protocol=proto,
                 flow_duration=_lognorm(rng, -0.5, 1.7, n), packet_count=pk,
                 byte_count=pk * _lognorm(rng, 5.6, 0.9, n))
    elif kind == "DoS Hulk":
        atk = rng.choice(ext_pool[:3], n)
        pk = 8 + rng.poisson(_lognorm(rng, 3.0, 0.7, n))
        d.update(src_ip=atk, dst_ip=SERVERS["web"], src_port=rng.integers(1024, 65535, n),
                 dst_port=80, protocol="TCP", flow_duration=_lognorm(rng, -2.0, 1.2, n),
                 packet_count=pk, byte_count=pk * rng.normal(90, 25, n).clip(40))
        ts = t0 + (t1 - t0) * (0.55 + 0.04 * rng.random(n))  # burst
    elif kind == "DDoS":
        pk = 2 + rng.poisson(4, n)
        d.update(src_ip=rng.choice(ext_pool, n), dst_ip=SERVERS["web"],
                 src_port=rng.integers(1024, 65535, n), dst_port=rng.choice([80, 443], n),
                 protocol=rng.choice(["TCP", "UDP"], n, p=[0.8, 0.2]),
                 flow_duration=_lognorm(rng, -4.0, 1.0, n), packet_count=pk,
                 byte_count=pk * rng.normal(70, 15, n).clip(40))
        ts = t0 + (t1 - t0) * (0.30 + 0.03 * rng.random(n))
    elif kind == "PortScan":
        pk = rng.choice([1, 2, 3], n, p=[0.6, 0.3, 0.1])
        scanner = rng.choice(ext_pool[10:13], n)
        d.update(src_ip=scanner, dst_ip=SERVERS["ssh"], src_port=rng.choice([40000, 40001, 52311], n),
                 dst_port=rng.integers(1, 65535, n), protocol="TCP",
                 flow_duration=_lognorm(rng, -7.0, 1.0, n), packet_count=pk,
                 byte_count=pk * rng.normal(58, 6, n).clip(40))
        ts = t0 + (t1 - t0) * (0.18 + 0.02 * rng.random(n))
    elif kind in ("SSH-Patator", "FTP-Patator"):
        port = 22 if kind.startswith("SSH") else 21
        pk = 12 + rng.poisson(_lognorm(rng, 2.2, 0.4, n))
        d.update(src_ip=rng.choice(ext_pool[20:24], n), dst_ip=SERVERS["ssh" if port == 22 else "ftp"],
                 src_port=rng.integers(1024, 65535, n), dst_port=port, protocol="TCP",
                 flow_duration=_lognorm(rng, 0.4, 0.5, n), packet_count=pk,
                 byte_count=pk * rng.normal(110, 30, n).clip(40))
        ts = t0 + (t1 - t0) * ((0.72 if port == 22 else 0.80) + 0.03 * rng.random(n))
    elif kind.startswith("Web Attack"):
        pk = 10 + rng.poisson(_lognorm(rng, 2.6, 0.6, n))
        d.update(src_ip=rng.choice(ext_pool[30:33], n), dst_ip=SERVERS["web"],
                 src_port=rng.integers(1024, 65535, n), dst_port=rng.choice([80, 443], n),
                 protocol="TCP", flow_duration=_lognorm(rng, 0.8, 0.7, n), packet_count=pk,
                 byte_count=pk * rng.normal(260, 80, n).clip(60))
        ts = t0 + (t1 - t0) * (0.88 + 0.03 * rng.random(n))
    else:  # Bot beaconing
        pk = 4 + rng.poisson(6, n)
        d.update(src_ip=rng.choice(clients[:3], n), dst_ip=rng.choice(ext_pool[40:42], n),
                 src_port=rng.integers(1024, 65535, n), dst_port=rng.choice([8080, 4444], n),
                 protocol="TCP", flow_duration=rng.normal(60, 15, n).clip(5), packet_count=pk,
                 byte_count=pk * rng.normal(75, 12, n).clip(40))
    df = pd.DataFrame(d)
    df["timestamp"] = pd.to_datetime(np.asarray(ts), unit="s")
    df["label"] = kind
    return df


def generate(n_rows=60_000, seed=42, dirty=True):
    rng = np.random.default_rng(seed)
    t1 = pd.Timestamp.now().floor("h").timestamp()
    t0 = t1 - 24 * 3600
    parts = []
    for kind, share in PROFILE.items():
        parts.append(_make(rng, kind, max(20, int(n_rows * share)), t0, t1))
    df = pd.concat(parts, ignore_index=True)

    # hard cases: a few stealthy attacks look like normal traffic and vice-versa
    benign_like = _make(rng, "BENIGN", len(df), t0, t1)
    atk = np.where(df["label"] != "BENIGN")[0]
    swap = rng.choice(atk, int(len(atk) * 0.02), replace=False)
    cols = ["src_port", "dst_port", "protocol", "flow_duration", "packet_count", "byte_count"]
    df.loc[swap, cols] = benign_like.loc[swap, cols].values

    df["flow_rate"] = df["byte_count"] / df["flow_duration"].replace(0, np.nan)
    df = df.sample(frac=1, random_state=seed).reset_index(drop=True)

    if dirty:
        k = len(df)
        df.loc[rng.choice(k, int(k * 0.004), replace=False), "flow_rate"] = np.inf
        df.loc[rng.choice(k, int(k * 0.004), replace=False), "byte_count"] = np.nan
        df.loc[rng.choice(k, 30, replace=False), "flow_duration"] = -1.0
        df = pd.concat([df, df.sample(int(k * 0.006), random_state=seed)], ignore_index=True)
    df["label"] = df["label"].astype(object)
    return df[["timestamp", "src_ip", "dst_ip", "src_port", "dst_port", "protocol",
               "flow_duration", "packet_count", "byte_count", "flow_rate", "label"]]


if __name__ == "__main__":
    out = generate(20000)
    print(out.label.value_counts())
