"""AI-Based Network Intrusion Detection & Security Monitoring System - SOC console (Streamlit GUI)."""
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
import joblib

sys.path.insert(0, str(Path(__file__).resolve().parent))
from nids import __version__, alerts as al, behavior, data_loader, eda, live, models, preprocess, report, synthetic
from nids.config import CAPTURE_DIR, DATA_DIR, REPORT_DIR, SEVERITIES, STATUSES

st.set_page_config(page_title="AI-NIDS | SOC Console", page_icon="🛡️", layout="wide")

SEV_COLORS = {"Low": "#2ca02c", "Medium": "#f2c037", "High": "#ff7f0e", "Critical": "#d62728"}
_NEW_ST = tuple(int(x) for x in st.__version__.split(".")[:2]) >= (1, 50)
WIDE = {"width": "stretch"} if _NEW_ST else {"use_container_width": True}
CLEAN_FILE = DATA_DIR / "clean_dataset.joblib"

st.markdown("""<style>
div[data-testid="stMetric"]{background:rgba(120,130,150,.10);border-radius:10px;padding:10px 14px}
.block-container{padding-top:1.6rem}
</style>""", unsafe_allow_html=True)


# ------------------------------------------------------------------ state
def init_state():
    ss = st.session_state
    if "init" in ss:
        return
    ss.init = True
    ss.df, ss.report, ss.notes, ss.split, ss.scored = None, None, {}, None, None
    ss.dataset_info = {}
    ss.bundle = models.load_bundle()
    if CLEAN_FILE.exists():
        try:
            ss.df, ss.report, ss.dataset_info = joblib.load(CLEAN_FILE)
        except Exception:
            pass


def show(fig):
    st.plotly_chart(fig, **WIDE)


def table(df, **kw):
    st.dataframe(df, hide_index=True, **WIDE, **kw)


# ------------------------------------------------------------------ pipeline helpers
def prepare(raw, group_families=True, source="uploaded"):
    ss = st.session_state
    unified, notes = data_loader.standardize(raw) if "label_raw" not in raw.columns else (raw, {})
    df, rep = preprocess.clean(unified, group_families=group_families)
    ss.df, ss.report, ss.notes = df, rep, notes
    ss.split, ss.scored = None, None
    ss.dataset_info = {
        "Source": source, "Rows after cleaning": f"{len(df):,}",
        "Normal / attack flows": f"{rep['normal_rows']:,} / {rep['attack_rows']:,}",
        "Attack categories": ", ".join(c for c in rep["class_counts"] if c != "Normal"),
        "Time span": f"{df.timestamp.min():%Y-%m-%d %H:%M} -> {df.timestamp.max():%Y-%m-%d %H:%M}",
    }
    joblib.dump((df, rep, ss.dataset_info), CLEAN_FILE, compress=3)
    return df, rep


def train(params, say=None):
    ss = st.session_state
    say = say or (lambda *_: None)
    say("Splitting data (stratified train / validation / test) ...")
    ss.split = preprocess.split_data(ss.df, extended=params["extended"], test_size=params["test"],
                                     val_size=params["val"], max_train_rows=params["max_train"])
    ss.bundle = models.train_all(ss.split, rf_trees=params["trees"], rf_depth=params["rf_depth"],
                                 dt_depth=params["dt_depth"], target_fpr=params["fpr"], progress=say)
    models.save_bundle(ss.bundle)
    return ss.bundle


def generate_alerts(data, window="10min", min_conf=0.5, use_iso=True, replace=True, tag="ML"):
    scored = models.score_flows(st.session_state.bundle, data, use_iso=use_iso)
    a = al.build_alerts(scored, window=window, min_conf=min_conf)
    a["source"] = tag
    if len(a):
        al.save_alerts(a, replace_source=tag if replace else None)
    st.session_state.scored = scored
    return scored, a


def default_params():
    return dict(extended=False, test=0.2, val=0.15, max_train=150_000, trees=100, rf_depth=None,
                dt_depth=12, fpr=0.03)


def quickstart(n_rows):
    with st.status("Running the complete demo pipeline ...", expanded=True) as s:
        st.write("1/4  Generating synthetic network traffic")
        raw = synthetic.generate(n_rows)
        st.write("2/4  Cleaning & preparing data")
        prepare(raw, source=f"Synthetic demo traffic ({n_rows:,} flows)")
        st.write("3/4  Training Logistic Regression, Decision Tree, Random Forest, Isolation Forest")
        train(default_params(), say=lambda m: st.write("     " + m))
        st.write("4/4  Scoring the held-out test set and raising alerts")
        generate_alerts(st.session_state.split["meta_test"])
        s.update(label="Demo pipeline finished - open the SOC Overview or Alerts page", state="complete")


# ------------------------------------------------------------------ pages
def page_overview():
    st.title("🛡️ SOC Overview")
    a = al.load_alerts()
    if a.empty:
        st.info("No alerts yet. Run the one-click demo, or go to **Data Preparation** to load your own dataset.")
        n = st.slider("Demo traffic size (flows)", 20_000, 200_000, 60_000, 10_000)
        if st.button("🚀 Run full demo pipeline", type="primary"):
            quickstart(n)
            st.rerun()
        return

    c = st.columns(6)
    c[0].metric("Total alerts", f"{len(a):,}")
    c[1].metric("🔴 Critical", int((a.severity == "Critical").sum()))
    c[2].metric("🟠 High", int((a.severity == "High").sum()))
    c[3].metric("🆕 New", int((a.status == "New").sum()))
    c[4].metric("🔎 Investigating", int((a.status == "Investigating").sum()))
    c[5].metric("✅ Resolved", int((a.status == "Resolved").sum()))

    span = (a.timestamp.max() - a.timestamp.min()).total_seconds()
    freq = "5min" if span < 6 * 3600 else "1h" if span < 5 * 86400 else "1D"
    t = a.assign(bin=a.timestamp.dt.floor(freq)).groupby(["bin", "category"])["flows"].sum().reset_index()
    left, right = st.columns([2, 1])
    with left:
        show(px.area(t, x="bin", y="flows", color="category", title=f"Threat trend (malicious flows per {freq})"))
    with right:
        sv = a.severity.value_counts().reindex(SEVERITIES).fillna(0).reset_index()
        sv.columns = ["Severity", "Alerts"]
        show(px.bar(sv, x="Severity", y="Alerts", color="Severity", color_discrete_map=SEV_COLORS,
                    title="Alerts by severity").update_layout(showlegend=False))
    l2, r2 = st.columns(2)
    with l2:
        top = (a.groupby("src_ip").agg(alerts=("alert_id", "size"), flows=("flows", "sum")).sort_values("flows")
               .tail(10).reset_index())
        show(px.bar(top, x="flows", y="src_ip", orientation="h", title="Top offending sources (malicious flows)"))
    with r2:
        cat = a.groupby("category").size().reset_index(name="Alerts")
        show(px.pie(cat, names="category", values="Alerts", hole=0.45, title="Alerts by category"))

    st.subheader("Latest high-priority alerts")
    hp = a[a.severity.isin(["Critical", "High"]) & (a.status == "New")].sort_values("timestamp", ascending=False)
    table(hp[["alert_id", "timestamp", "category", "severity", "confidence", "src_ip", "dst_ip", "flows"]].head(10))

    if st.session_state.bundle is not None:
        m = st.session_state.bundle["metrics"]
        m = m[(m.Split == "test") & (m.Model == "Random Forest")].iloc[0]
        st.caption(f"Model snapshot (Random Forest, test set): accuracy {m.Accuracy:.2%} · recall {m.Recall:.2%} · "
                   f"false-positive rate {m.FPR:.2%}")


def page_data():
    st.title("📥 Module 1 - Network Traffic Data Preparation")
    src = st.radio("Data source", ["Demo traffic (synthetic)", "Upload CSV file(s)", "Folder on this machine"],
                   horizontal=True)
    raw, label = None, ""
    if src.startswith("Demo"):
        n = st.slider("Number of flows", 20_000, 300_000, 80_000, 10_000)
        if st.button("Generate demo traffic", type="primary"):
            raw, label = synthetic.generate(n), f"Synthetic demo traffic ({n:,} flows)"
    elif src.startswith("Upload"):
        up = st.file_uploader("CIC-IDS2017 / CSE-CIC-IDS2018 / UNSW-NB15 CSV files", type="csv",
                              accept_multiple_files=True)
        c1, c2 = st.columns(2)
        frac = c1.slider("Sample fraction per file", 0.05, 1.0, 1.0, 0.05)
        mx = c2.number_input("Max rows (0 = no limit)", 0, 5_000_000, 300_000, 50_000)
        if up and st.button("Load files", type="primary"):
            with st.spinner("Reading and unifying columns ..."):
                raw, nt = data_loader.load_paths(up, frac, mx or None)
                st.session_state.notes = nt
            label = f"{len(up)} uploaded file(s)"
    else:
        folder = st.text_input("Folder containing the dataset CSVs", str(Path.home() / "datasets"))
        files = data_loader.find_csvs(folder) if Path(folder).expanduser().exists() else []
        st.caption(f"{len(files)} CSV files found")
        pick = st.multiselect("Files to use", files, default=files[:1], format_func=lambda p: p.name)
        c1, c2 = st.columns(2)
        frac = c1.slider("Sample fraction per file", 0.05, 1.0, 0.3, 0.05)
        mx = c2.number_input("Max rows (0 = no limit)", 0, 5_000_000, 300_000, 50_000)
        if pick and st.button("Load files", type="primary"):
            with st.spinner("Reading large CSVs in chunks ..."):
                raw, nt = data_loader.load_paths(pick, frac, mx or None)
                st.session_state.notes = nt
            label = f"{len(pick)} file(s) from {folder}"

    group = st.checkbox("Group attack sub-types into families (DoS Hulk/GoldenEye/slowloris -> DoS ...)", True)
    if raw is not None:
        with st.spinner("Cleaning ..."):
            prepare(raw, group_families=group, source=label)
        st.success("Dataset loaded and cleaned.")

    df, rep = st.session_state.df, st.session_state.report
    if df is None:
        st.info("Choose a data source above. Tip: start with the demo data to see the whole system working.")
        return
    for k, v in st.session_state.notes.items():
        if k in ("timestamp", "src_ip", "dst_ip", "label"):
            st.warning(v)

    st.subheader("Cleaning report")
    c = st.columns(5)
    c[0].metric("Rows loaded", f"{rep['rows_loaded']:,}")
    c[1].metric("Duplicates removed", f"{rep['duplicates_removed']:,}")
    c[2].metric("Invalid rows removed", f"{rep['invalid_rows_removed']:,}")
    c[3].metric("inf values fixed", f"{rep['inf_values']:,}")
    c[4].metric("Rows after cleaning", f"{rep['rows_final']:,}")
    l, r = st.columns(2)
    with l:
        st.markdown("**Missing values per column (imputed with train-set median)**")
        miss = rep["missing_values"]
        table(pd.DataFrame({"column": list(miss), "missing": list(miss.values())}) if miss
              else pd.DataFrame({"result": ["no missing values"]}))
        st.markdown("**Data types**")
        table(pd.DataFrame({"column": df.columns[:14], "dtype": [str(t) for t in df.dtypes[:14]]}))
    with r:
        st.markdown("**Label cleaning (inconsistent labels -> one vocabulary)**")
        table(rep["label_mapping"])

    st.subheader("Class balance")
    cc = pd.Series(rep["class_counts"]).reset_index()
    cc.columns = ["Category", "Flows"]
    a, b = st.columns([2, 1])
    with a:
        show(px.bar(cc, x="Category", y="Flows", color="Category", log_y=True,
                    title="Flows per class (log scale)").update_layout(showlegend=False))
    with b:
        st.metric("Normal : attack imbalance", f"{rep['imbalance_ratio']} : 1")
        st.caption("Handled with class-weighted learning (`balanced`) and stratified splitting; "
                   "accuracy alone is misleading on imbalanced data, so recall and FPR are reported.")
        st.info("**Leakage control:** duplicates are removed *before* splitting, the split is stratified, and "
                "imputer + scaler are fitted on the **training set only**. Isolation Forest sees only normal training flows.")
    with st.expander("Preview cleaned data"):
        table(df.head(200))


def page_eda():
    st.title("🔎 Module 2 - Exploratory Security Data Analysis")
    df = st.session_state.df
    if df is None:
        st.warning("Load data first (Data Preparation page).")
        return
    tabs = st.tabs(["Distribution", "Protocols", "Duration", "Packets & bytes", "Time", "Ports", "Correlation"])
    with tabs[0]:
        l, r = st.columns(2)
        with l: show(eda.class_distribution(df))
        with r: show(eda.attack_frequency(df))
    with tabs[1]:
        f1, f2 = eda.protocol_volume(df)
        l, r = st.columns(2)
        with l: show(f1)
        with r: show(f2)
        st.caption("Unusual protocol mixes (e.g. lots of ICMP or UDP) often indicate scanning or flooding.")
    with tabs[2]:
        h, b = eda.duration_distribution(df)
        show(h); show(b)
        st.caption("Scans and floods use very short flows; beaconing bots keep long, regular flows.")
    with tabs[3]:
        f, t = eda.packet_byte_anomalies(df)
        show(f)
        table(t)
    with tabs[4]:
        f1, f2 = eda.traffic_over_time(df)
        show(f1); show(f2)
        st.caption("Attack campaigns appear as sharp bursts - compare with the normal daily rhythm.")
    with tabs[5]:
        f1, f2 = eda.port_distributions(df)
        l, r = st.columns(2)
        with l: show(f1)
        with r: show(f2)
        st.markdown("**Hosts scanning many ports / flooding (host-behaviour analytics)**")
        sus = behavior.suspicious_hosts(df)
        table(sus if len(sus) else pd.DataFrame({"result": ["no scanning / flooding hosts above thresholds"]}))
    with tabs[6]:
        show(eda.correlation(df))
        st.caption("Highly correlated features (packets vs bytes) carry redundant information; tree models handle this well.")


def page_ml():
    st.title("🤖 Module 3 - Intrusion Detection with Machine Learning")
    ss = st.session_state
    if ss.df is None:
        st.warning("Load data first (Data Preparation page).")
        return
    with st.expander("⚙️ Training settings", expanded=ss.bundle is None):
        c = st.columns(4)
        p = default_params()
        p["test"] = c[0].slider("Test size", 0.1, 0.4, 0.2, 0.05)
        p["val"] = c[1].slider("Validation size", 0.05, 0.3, 0.15, 0.05)
        p["trees"] = c[2].slider("Random Forest trees", 20, 400, 100, 20)
        p["dt_depth"] = c[3].slider("Decision Tree max depth", 3, 30, 12)
        c = st.columns(4)
        p["fpr"] = c[0].slider("Isolation Forest target false-positive rate", 0.005, 0.15, 0.03, 0.005,
                               help="Threshold is set on NORMAL validation traffic only.")
        p["max_train"] = c[1].number_input("Max training rows", 20_000, 1_000_000, 150_000, 10_000)
        n_ext = sum(1 for x in ss.df.columns if x.startswith("x_"))
        p["extended"] = c[2].checkbox(f"Extended features (+{n_ext} dataset columns)", False, disabled=n_ext == 0,
                                      help="Better accuracy on full CIC/UNSW CSVs, but cannot score live Zeek/tshark flows.")
        if st.button("🧠 Train all models", type="primary"):
            with st.status("Training ...", expanded=True) as s:
                train(p, say=lambda m: st.write(m))
                s.update(label="Training complete", state="complete")

    b = ss.bundle
    if b is None:
        return
    st.caption("Split sizes: " + " · ".join(f"{k} {v:,}" for k, v in b["sizes"].items()) +
               f" · features: {len(b['feature_cols'])} · "
               + ("extended feature set" if b["extended"] else "core feature set (live-capable)"))
    m = b["metrics"]
    t1, t2, t3, t4, t5 = st.tabs(["Model comparison", "ROC & confusion matrix", "Attack-type classifier",
                                  "Explainability", "Training time"])
    with t1:
        cfg = {c: st.column_config.NumberColumn(format="%.4f") for c in
               ["Accuracy", "Precision", "Recall", "F1", "FPR", "FNR", "ROC_AUC"]}
        part = st.radio("Evaluate on", ["test", "val"], horizontal=True, format_func=lambda x: {
            "test": "Test set (final)", "val": "Validation set"}[x])
        table(m[m.Split == part].drop(columns="Split"), column_config=cfg)
        d = m[m.Split == "test"].melt(id_vars="Model", value_vars=["Precision", "Recall", "F1", "FPR"])
        show(px.bar(d, x="Model", y="value", color="variable", barmode="group",
                    title="Precision / Recall / F1 / False-positive rate (test)"))
        st.caption("**FPR** = share of normal traffic wrongly flagged (analyst workload). "
                   "**Recall** = share of attacks caught. A good IDS keeps FPR low while recall stays high.")
    with t2:
        fig = go.Figure()
        for n, (f, t, auc) in b["roc"].items():
            fig.add_trace(go.Scatter(x=f, y=t, mode="lines", name=f"{n} (AUC {auc:.3f})"))
        fig.add_trace(go.Scatter(x=[0, 1], y=[0, 1], mode="lines", name="chance", line=dict(dash="dot")))
        fig.update_layout(title="ROC curves (test set)", xaxis_title="False-positive rate",
                          yaxis_title="True-positive rate")
        show(fig)
        pick = st.selectbox("Confusion matrix for", list(b["cms"]))
        show(px.imshow(b["cms"][pick], text_auto=True, x=["Pred Normal", "Pred Attack"],
                       y=["Actual Normal", "Actual Attack"], color_continuous_scale="Blues",
                       title=f"Confusion matrix - {pick}"))
    with t3:
        st.markdown("Random Forest multi-class report on the test set (which **type** of attack?)")
        rep = b["multiclass_report"].round(3).reset_index().rename(columns={"index": "class"})
        table(rep)
        labels, cm = b["multiclass_cm"]
        show(px.imshow(cm, text_auto=True, x=labels, y=labels, color_continuous_scale="Blues",
                       labels=dict(x="Predicted", y="Actual"), title="Multi-class confusion matrix"))
        if b["merged_classes"]:
            st.info(f"Very rare classes merged into 'Other Attack': {', '.join(b['merged_classes'])}")
    with t4:
        fi = b["feature_importance"].head(15).reset_index()
        fi.columns = ["feature", "importance"]
        show(px.bar(fi, x="importance", y="feature", orientation="h", title="Random Forest feature importance")
             .update_layout(yaxis={"categoryorder": "total ascending"}))
        st.markdown("**Decision Tree rules (top levels) - interpretable detection logic**")
        st.code(b["tree_rules"])
    with t5:
        table(pd.DataFrame({"model": list(b["train_times"]), "seconds": list(b["train_times"].values())}))
        st.caption("Isolation Forest was fitted on normal traffic only - it needs no attack labels.")


def page_alerts():
    st.title("🚨 Module 4 - Threat Classification & Alerts")
    ss = st.session_state
    with st.expander("⚡ Generate alerts from the trained model", expanded=al.load_alerts().empty):
        if ss.bundle is None or ss.df is None:
            st.warning("Train a model first (ML Detection page).")
        else:
            opts = []
            if ss.split is not None:
                opts.append("Held-out test split (recommended - unseen data)")
            opts.append("Entire cleaned dataset")
            c = st.columns(4)
            where = c[0].selectbox("Score", opts)
            window = c[1].selectbox("Group alerts per", ["1min", "5min", "10min", "30min", "1h"], 2,
                                    help="Flows from the same source & category in one window become ONE alert.")
            conf = c[2].slider("Minimum confidence", 0.3, 0.95, 0.5, 0.05)
            iso = c[3].checkbox("Include Isolation Forest anomalies", True)
            if st.button("Generate alerts", type="primary"):
                data = ss.split["meta_test"] if where.startswith("Held") else ss.df
                with st.spinner("Scoring flows ..."):
                    scored, a = generate_alerts(data, window, conf, iso, replace=True)
                st.success(f"{int(scored.flagged.sum()):,} suspicious flows -> {len(a):,} alerts "
                           f"(alert-volume reduction x{max(1, int(scored.flagged.sum()) // max(1, len(a)))})")
                if ss.split is not None and where.startswith("Held"):
                    y = ss.split["yb_test"]
                    tp = int(((scored.flagged.values) & (y == 1)).sum())
                    fp = int(((scored.flagged.values) & (y == 0)).sum())
                    st.caption(f"Ground truth check: {tp:,} true detections, {fp:,} false alarms "
                               f"(FPR {fp / max(1, int((y == 0).sum())):.2%}).")

    a = al.load_alerts()
    if a.empty:
        return
    st.subheader("Alert queue")
    c = st.columns(5)
    sev = c[0].multiselect("Severity", SEVERITIES, SEVERITIES)
    sta = c[1].multiselect("Status", STATUSES, STATUSES)
    cat = c[2].multiselect("Category", sorted(a.category.unique()))
    srcs = c[3].multiselect("Source", sorted(a.source.unique()), sorted(a.source.unique()))
    q = c[4].text_input("Search IP / text")
    f = a[a.severity.isin(sev) & a.status.isin(sta) & a.source.isin(srcs)]
    if cat:
        f = f[f.category.isin(cat)]
    if q:
        f = f[f[["src_ip", "dst_ip", "description", "analyst_notes"]].astype(str).apply(
            lambda col: col.str.contains(q, case=False)).any(axis=1)]
    f = f.sort_values(["timestamp"], ascending=False)
    show_cols = ["alert_id", "timestamp", "category", "severity", "confidence", "status", "analyst_notes",
                 "src_ip", "dst_ip", "flows", "source"]
    edited = st.data_editor(
        f[show_cols].head(1500), hide_index=True, key="alert_editor", **WIDE,
        disabled=[c for c in show_cols if c not in ("status", "analyst_notes")],
        column_config={
            "status": st.column_config.SelectboxColumn("Status", options=STATUSES, required=True),
            "analyst_notes": st.column_config.TextColumn("Analyst notes", width="large"),
            "confidence": st.column_config.ProgressColumn("Confidence", min_value=0, max_value=1, format="%.2f"),
        })
    b1, b2, b3 = st.columns([1, 1, 2])
    if b1.button("💾 Save status & notes", type="primary"):
        n = al.update_alerts(edited[["alert_id", "status", "analyst_notes"]])
        st.success(f"Saved {n} alerts")
    new_stat = b2.selectbox("Bulk set status for filtered", STATUSES, label_visibility="collapsed")
    if b3.button(f"Apply '{new_stat}' to {len(f):,} filtered alerts"):
        bulk = f[["alert_id", "analyst_notes"]].assign(status=new_stat)
        al.update_alerts(bulk[["alert_id", "status", "analyst_notes"]])
        st.rerun()
    st.download_button("⬇️ Export alerts (CSV)", a.to_csv(index=False).encode(), "alerts.csv", "text/csv")

    st.subheader("Alert investigation")
    sel = st.selectbox("Alert", f.alert_id.tolist()[:1500]) if len(f) else None
    if sel:
        r = a[a.alert_id == sel].iloc[0]
        l, rr = st.columns(2)
        with l:
            st.markdown(f"### {r.alert_id} - {r.category}")
            st.markdown(f"**Severity:** {r.severity}  \n**Confidence:** {r.confidence:.0%}  \n"
                        f"**First seen:** {r.timestamp}  \n**Last seen:** {r.last_seen}  \n"
                        f"**Source -> destination:** `{r.src_ip}` -> `{r.dst_ip}`  \n"
                        f"**Flows:** {r.flows:,} · **Distinct dst ports:** {r.dst_ports} · "
                        f"**Bytes:** {r.total_bytes:,.0f}")
        with rr:
            st.markdown(f"**What it means:** {r.description}")
            st.markdown(f"**Recommended action:** {r.recommended_action}")
        sc = ss.scored
        if sc is not None and r.source == "ML":
            ev = sc[(sc.final_category == r.category) & (sc.timestamp >= r.timestamp) &
                    (sc.timestamp <= r.last_seen + pd.Timedelta(seconds=1))]
            if not r.src_ip.endswith("sources"):
                ev = ev[ev.src_ip.astype(str) == r.src_ip]
            with st.expander(f"Evidence: {len(ev):,} flows behind this alert"):
                table(ev[["timestamp", "src_ip", "src_port", "dst_ip", "dst_port", "protocol", "flow_duration",
                          "packet_count", "byte_count", "final_conf"]].head(300))


def _score_flows_page(flows, tag, run_suricata_on=None):
    """Score live/imported flows, raise alerts and show them."""
    ss = st.session_state
    if ss.bundle is None:
        st.error("Train a model first (ML Detection page).")
        return
    if ss.bundle["extended"]:
        st.error("The current model uses the *extended* feature set, which needs full dataset columns. "
                 "Retrain with the core feature set to score live traffic.")
        return
    scored, a = generate_alerts(flows, "1min", 0.5, True, replace=False, tag=tag)
    c = st.columns(3)
    c[0].metric("Flows analysed", f"{len(flows):,}")
    c[1].metric("Suspicious flows", f"{int(scored.flagged.sum()):,}")
    c[2].metric("Alerts raised", len(a))
    if len(a):
        table(a[["timestamp", "category", "severity", "confidence", "src_ip", "dst_ip", "flows"]])
    else:
        st.success("No suspicious activity found.")
    sus = behavior.suspicious_hosts(flows, "1min", 20, 200, 10)
    if len(sus):
        st.markdown("**Host behaviour findings**")
        table(sus)


def page_live():
    st.title("📡 Live Monitoring & Tool Integration")
    ts = live.tool_status()
    st.write("  ".join(f"{'🟢' if v else '🔴'} `{k}`" for k, v in ts.items()))
    tabs = st.tabs(["Live capture", "Analyse PCAP", "Import Zeek / Suricata logs", "Score a CSV"])
    with tabs[0]:
        c = st.columns(3)
        iface = c[0].selectbox("Interface", live.list_interfaces())
        secs = c[1].slider("Capture seconds", 5, 300, 30)
        also_s = c[2].checkbox("Also run Suricata on the capture", bool(ts["suricata"]), disabled=not ts["suricata"])
        st.caption("Capture needs the `wireshark` group (the installer adds you - log out/in once) or run with sudo. "
                   "Only monitor networks you own or are authorised to test.")
        if st.button("▶ Capture & analyse", type="primary"):
            try:
                with st.spinner(f"Capturing {secs}s on {iface} ..."):
                    pcap = live.capture(iface, secs)
                flows = live.pcap_to_flows(pcap)
                st.success(f"Saved {pcap.name}: {len(flows):,} flows")
                _score_flows_page(flows, "ML-Live")
                if also_s:
                    _suricata(pcap)
            except Exception as e:
                st.error(str(e))
    with tabs[1]:
        up = st.file_uploader("PCAP / PCAPNG file (e.g. saved from Wireshark)", type=["pcap", "pcapng", "cap"])
        engine = st.radio("Flow engine", ["tshark (built-in aggregation)", "Zeek conn.log"], horizontal=True)
        also_s = st.checkbox("Also run Suricata", bool(ts["suricata"]), disabled=not ts["suricata"], key="s2")
        if up and st.button("Analyse PCAP", type="primary"):
            path = CAPTURE_DIR / up.name
            path.write_bytes(up.getbuffer())
            try:
                flows = live.parse_zeek_conn(live.run_zeek(path)) if engine.startswith("Zeek") else live.pcap_to_flows(path)
                _score_flows_page(flows, "ML-PCAP")
                if also_s:
                    _suricata(path)
            except Exception as e:
                st.error(str(e))
    with tabs[2]:
        l, r = st.columns(2)
        with l:
            z = st.file_uploader("Zeek conn.log", type=["log", "txt", "json"], key="zeek")
            if z and st.button("Score Zeek flows"):
                try:
                    _score_flows_page(live.parse_zeek_conn(z.getvalue().decode(errors="ignore")), "ML-Zeek")
                except Exception as e:
                    st.error(f"Could not parse conn.log: {e}")
        with r:
            s = st.file_uploader("Suricata eve.json", type=["json", "log"], key="eve")
            if s and st.button("Import Suricata alerts"):
                a = live.parse_suricata_eve(s.getvalue().decode(errors="ignore"))
                if len(a):
                    al.save_alerts(a)
                    st.success(f"Imported {len(a)} Suricata alerts - see the Alerts page.")
                    table(a[["timestamp", "category", "severity", "src_ip", "dst_ip", "description"]].head(200))
                else:
                    st.warning("No alert events found in that file.")
    with tabs[3]:
        f = st.file_uploader("CSV in CIC-IDS / UNSW-NB15 / unified format", type="csv", key="csvscore")
        if f and st.button("Score CSV"):
            raw = data_loader.load_csv(f, max_rows=200_000)
            uni, _ = data_loader.standardize(raw)
            df, _ = preprocess.clean(uni)
            _score_flows_page(df, "ML-CSV")


def _suricata(pcap):
    try:
        eve = live.run_suricata(pcap)
        a = live.parse_suricata_eve(eve)
        if len(a):
            al.save_alerts(a)
            st.success(f"Suricata raised {len(a)} signature alerts")
            table(a[["timestamp", "category", "severity", "src_ip", "dst_ip", "description"]])
        else:
            st.info("Suricata found no signature matches.")
    except Exception as e:
        st.warning(str(e))


def page_report():
    st.title("📝 Incident Investigation Report")
    a = al.load_alerts()
    c = st.columns(3)
    title = c[0].text_input("Report title", "Network Intrusion Incident Report")
    analyst = c[1].text_input("Analyst", "Junior Security Analyst")
    org = c[2].text_input("Organisation", "SOC Lab")
    concl = st.text_area("Analyst conclusion (optional)", "", height=100)
    if st.button("Generate report", type="primary"):
        md = report.build_report(a, st.session_state.bundle, st.session_state.dataset_info, title, analyst, org, concl)
        st.session_state.report_md = md
        stamp = time.strftime("%Y%m%d_%H%M%S")
        (REPORT_DIR / f"incident_report_{stamp}.md").write_text(md)
    md = st.session_state.get("report_md")
    if md:
        d1, d2, _ = st.columns([1, 1, 3])
        d1.download_button("⬇️ Markdown", md, "incident_report.md", "text/markdown")
        try:
            d2.download_button("⬇️ HTML (print to PDF)", report.to_html(md), "incident_report.html", "text/html")
        except ImportError:
            st.caption("Install the `markdown` package for HTML export.")
        st.caption(f"A copy is saved in {REPORT_DIR}")
        st.divider()
        st.markdown(md)


def page_help():
    st.title("ℹ️ Help & Lab guide")
    st.markdown(f"""
**AI-NIDS v{__version__}** - Module map: Data Prep -> EDA -> ML Detection -> Alerts -> Live/Tools -> Report.

**Where data lives:** `~/.nids` (alerts DB, trained model, reports, captures).

**Datasets (download manually, then use *Data Preparation -> Folder* or *Upload*):**
- CIC-IDS2017 - unb.ca/cic/datasets/ids-2017.html (use *TrafficLabelling* CSVs: they include IPs and timestamps)
- CSE-CIC-IDS2018 - unb.ca/cic/datasets/ids-2018.html
- UNSW-NB15 - research.unsw.edu.au/projects/unsw-nb15-dataset

**Safe lab traffic generation (only against your OWN lab VMs, e.g. Metasploitable on a host-only network):**
```
nmap -sS -p 1-5000 <lab-target-ip>        # port-scan pattern
hping3 -S --flood -p 80 <lab-target-ip>    # SYN flood (lab only!)
hydra -l test -P pw.txt ssh://<lab-target-ip>   # brute-force pattern
```
Capture on the Kali interface from the **Live Monitoring** page and watch the alerts appear.
""")


# ------------------------------------------------------------------ main
init_state()
PAGES = {
    "🏠 SOC Overview": page_overview, "📥 Data Preparation": page_data, "🔎 Exploratory Analysis": page_eda,
    "🤖 ML Detection": page_ml, "🚨 Alerts": page_alerts, "📡 Live Monitoring": page_live,
    "📝 Incident Report": page_report, "ℹ️ Help": page_help,
}
with st.sidebar:
    st.markdown("## 🛡️ AI-NIDS")
    st.caption("Network Intrusion Detection & Security Monitoring")
    choice = st.radio("Navigation", list(PAGES), label_visibility="collapsed")
    st.divider()
    st.caption(f"Dataset: {'loaded' if st.session_state.df is not None else 'none'} · "
               f"Model: {'trained' if st.session_state.bundle is not None else 'none'}")
    with st.expander("Danger zone"):
        if st.checkbox("I want to delete all alerts") and st.button("Delete alerts"):
            al.clear_alerts()
            st.rerun()
PAGES[choice]()
