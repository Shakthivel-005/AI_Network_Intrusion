"""Host-level behaviour analytics: flow-level ML cannot see 'one IP touching 3000 ports'.
This module aggregates per source IP and flags scanners, flooders and beacons with simple rules."""
import pandas as pd


def host_summary(df: pd.DataFrame, window="1min"):
    d = df.copy()
    d["bucket"] = d["timestamp"].dt.floor(window)
    g = d.groupby(["src_ip", "bucket"]).agg(
        flows=("dst_port", "size"), unique_dst_ports=("dst_port", "nunique"),
        unique_dst_ips=("dst_ip", "nunique"), bytes=("byte_count", "sum"),
        packets=("packet_count", "sum"), median_duration=("flow_duration", "median")).reset_index()
    return g


def suspicious_hosts(df, window="5min", port_thr=30, flow_thr=400, host_thr=20):
    g = host_summary(df, window)
    g["scan_suspect"] = (g.unique_dst_ports >= port_thr) | (g.unique_dst_ips >= host_thr)
    g["flood_suspect"] = g.flows >= flow_thr
    flag = g[g.scan_suspect | g.flood_suspect]
    if flag.empty:
        return flag
    agg = flag.groupby("src_ip").agg(
        windows=("bucket", "nunique"), peak_flows=("flows", "max"),
        peak_unique_ports=("unique_dst_ports", "max"), peak_unique_hosts=("unique_dst_ips", "max"),
        total_bytes=("bytes", "sum"), scan=("scan_suspect", "any"), flood=("flood_suspect", "any"))
    agg["behaviour"] = agg.apply(lambda r: " + ".join([x for x, f in
                         (("Port scanning", r.scan), ("Flooding", r.flood)) if f]), axis=1)
    return agg.drop(columns=["scan", "flood"]).sort_values("peak_flows", ascending=False).reset_index()
