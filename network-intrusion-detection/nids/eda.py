"""Module 2 - exploratory security data analysis (Plotly figures)."""
import numpy as np
import pandas as pd
import plotly.express as px

from .preprocess import build_features

COLORS = {"Normal": "#2ca02c", "Attack": "#d62728"}


def _tag(df):
    return df["is_attack"].map({0: "Normal", 1: "Attack"})


def _sample(df, n=60_000):
    return df.sample(n=n, random_state=1) if len(df) > n else df


def class_distribution(df):
    c = _tag(df).value_counts().reset_index()
    c.columns = ["Traffic", "Flows"]
    return px.pie(c, names="Traffic", values="Flows", hole=0.5, color="Traffic",
                  color_discrete_map=COLORS, title="Normal vs malicious traffic")


def attack_frequency(df):
    a = df[df.is_attack == 1]["category"].value_counts().reset_index()
    a.columns = ["Category", "Flows"]
    return px.bar(a, x="Flows", y="Category", orientation="h", color="Category",
                  title="Attack frequency by category").update_layout(showlegend=False,
                                                                      yaxis={"categoryorder": "total ascending"})


def protocol_volume(df):
    d = df.assign(Traffic=_tag(df)).groupby(["protocol_group", "Traffic"]).agg(
        Flows=("byte_count", "size"), Bytes=("byte_count", "sum")).reset_index()
    f1 = px.bar(d, x="protocol_group", y="Flows", color="Traffic", barmode="group",
                color_discrete_map=COLORS, title="Flows by protocol", log_y=True)
    f2 = px.bar(d, x="protocol_group", y="Bytes", color="Traffic", barmode="group",
                color_discrete_map=COLORS, title="Bytes by protocol", log_y=True)
    return f1, f2


def duration_distribution(df):
    s = _sample(df).assign(Traffic=_tag(df))
    s["log10_duration"] = np.log10(s["flow_duration"].clip(lower=1e-6))
    h = px.histogram(s, x="log10_duration", color="Traffic", nbins=70, barmode="overlay", opacity=0.65,
                     color_discrete_map=COLORS, title="Connection duration (log10 seconds)")
    b = px.box(s, x="category", y="flow_duration", log_y=True, color="category",
               title="Duration by category (log scale)").update_layout(showlegend=False)
    return h, b


def packet_byte_anomalies(df):
    s = _sample(df, 8000)
    f = px.scatter(s, x="packet_count", y="byte_count", color="category", log_x=True, log_y=True,
                   opacity=0.6, title="Packets vs bytes per flow (outliers = anomalies)")
    lb = np.log1p(df["byte_count"].clip(lower=0))
    z = (lb - lb.mean()) / (lb.std() + 1e-9)
    lp = np.log1p(df["packet_count"].clip(lower=0))
    zp = (lp - lp.mean()) / (lp.std() + 1e-9)
    out = (z.abs() > 3) | (zp.abs() > 3)
    t = (pd.DataFrame({"Traffic": _tag(df), "outlier": out}).groupby("Traffic")["outlier"]
         .agg(["sum", "size"]).rename(columns={"sum": "Outlier flows (|z|>3)", "size": "Total flows"}))
    t["Outlier %"] = (100 * t["Outlier flows (|z|>3)"] / t["Total flows"]).round(2)
    return f, t.reset_index()


def traffic_over_time(df):
    span = (df["timestamp"].max() - df["timestamp"].min()).total_seconds()
    freq = "1min" if span < 3 * 3600 else "5min" if span < 2 * 86400 else "1h"
    d = df.assign(bin=df["timestamp"].dt.floor(freq), Traffic=_tag(df))
    a = d.groupby(["bin", "Traffic"]).size().reset_index(name="Flows")
    f1 = px.line(a, x="bin", y="Flows", color="Traffic", color_discrete_map=COLORS,
                 title=f"Flows over time ({freq} bins)")
    m = d[d.is_attack == 1].groupby(["bin", "category"]).size().reset_index(name="Flows")
    f2 = px.area(m, x="bin", y="Flows", color="category", title="Attack traffic over time by category")
    return f1, f2


def port_distributions(df):
    d = df.assign(Traffic=_tag(df)).dropna(subset=["dst_port"])
    top = d["dst_port"].astype(int).value_counts().head(15).index
    t = d[d["dst_port"].astype(int).isin(top)].assign(port=lambda x: x["dst_port"].astype(int).astype(str))
    t = t.groupby(["port", "Traffic"]).size().reset_index(name="Flows")
    f1 = px.bar(t, x="port", y="Flows", color="Traffic", color_discrete_map=COLORS, barmode="stack",
                title="Top 15 destination ports")
    s = _sample(d, 40_000)
    f2 = px.histogram(s, x="src_port", color="Traffic", nbins=60, barmode="overlay", opacity=0.6,
                      color_discrete_map=COLORS, title="Source port distribution")
    return f1, f2


def correlation(df):
    X = build_features(_sample(df, 30_000), extended=False).drop(columns=["proto_OTHER"], errors="ignore")
    c = X.corr().round(2)
    return px.imshow(c, text_auto=True, zmin=-1, zmax=1, color_continuous_scale="RdBu_r",
                     title="Correlation of traffic features (log-scaled)", aspect="auto")
