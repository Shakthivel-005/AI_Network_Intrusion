"""Incident investigation report generator (Markdown + HTML)."""
import datetime as dt
import pandas as pd


def md_table(df: pd.DataFrame, max_rows=15):
    if df is None or len(df) == 0:
        return "_No data._\n"
    d = df.head(max_rows).astype(str)
    head = "| " + " | ".join(d.columns) + " |\n|" + "---|" * len(d.columns) + "\n"
    body = "".join("| " + " | ".join(r) + " |\n" for r in d.values)
    return head + body


def build_report(alerts: pd.DataFrame, bundle=None, dataset_info=None, title="Network Intrusion Incident Report",
                 analyst="Junior Security Analyst", org="SOC", conclusions=""):
    now = dt.datetime.now().strftime("%Y-%m-%d %H:%M")
    L = [f"# {title}", f"**Organisation:** {org}  \n**Prepared by:** {analyst}  \n**Generated:** {now}\n"]
    n = len(alerts)
    L.append("## 1. Executive summary")
    if n == 0:
        L.append("No alerts were recorded during the analysed period.\n")
    else:
        sev = alerts["severity"].value_counts()
        crit = int(sev.get("Critical", 0)) + int(sev.get("High", 0))
        top = alerts["category"].value_counts().index[0]
        L.append(f"The monitoring system raised **{n} alerts** between "
                 f"{alerts['timestamp'].min():%Y-%m-%d %H:%M} and {alerts['last_seen'].max():%Y-%m-%d %H:%M}. "
                 f"**{crit}** were High/Critical. The most frequent threat category was **{top}**. "
                 f"{int((alerts['status']=='Resolved').sum())} alerts are resolved, "
                 f"{int((alerts['status']=='Investigating').sum())} under investigation and "
                 f"{int((alerts['status']=='New').sum())} still new.\n")
    if dataset_info:
        L.append("## 2. Data analysed")
        L.append("\n".join(f"- **{k}:** {v}" for k, v in dataset_info.items()) + "\n")
    if bundle is not None:
        m = bundle["metrics"]
        t = m[m.Split == "test"][["Model", "Accuracy", "Precision", "Recall", "F1", "FPR", "ROC_AUC"]].round(4)
        L.append("## 3. Detection performance (held-out test set)")
        L.append(md_table(t))
        best = t.sort_values("F1", ascending=False).iloc[0]
        L.append(f"Best F1: **{best['Model']}** (F1 {best['F1']}, false-positive rate {best['FPR']}). "
                 "False positives are the main source of analyst workload, so FPR is monitored alongside recall.\n")
    L.append("## 4. Alert summary")
    if n:
        L.append("**By severity**\n\n" + md_table(alerts["severity"].value_counts().rename_axis("Severity")
                                                    .reset_index(name="Alerts")))
        L.append("**By category**\n\n" + md_table(alerts["category"].value_counts().rename_axis("Category")
                                                    .reset_index(name="Alerts")))
        top_src = (alerts.groupby("src_ip").agg(alerts=("alert_id", "size"), flows=("flows", "sum"),
                                                categories=("category", lambda s: ", ".join(sorted(set(s)))))
                   .sort_values("flows", ascending=False).reset_index().rename(columns={"src_ip": "Source IP"}))
        L.append("## 5. Top offending source IPs\n\n" + md_table(top_src, 10))
        crit_df = alerts[alerts.severity.isin(["Critical", "High"])].sort_values("timestamp")
        L.append("## 6. Incident timeline (High / Critical)\n\n" +
                 md_table(crit_df[["alert_id", "timestamp", "category", "severity", "src_ip", "dst_ip", "flows"]], 20))
        worked = alerts[(alerts.status != "New") | (alerts.analyst_notes.fillna("") != "")]
        L.append("## 7. Investigation findings")
        if len(worked):
            for r in worked.head(25).itertuples():
                L.append(f"- **{r.alert_id}** ({r.category}, {r.severity}, {r.status}): "
                         f"{r.analyst_notes or 'no notes yet'}")
            L.append("")
        else:
            L.append("_No analyst notes recorded yet._\n")
        acts = (alerts.drop_duplicates("category")[["category", "recommended_action"]]
                .rename(columns={"category": "Category", "recommended_action": "Recommended action"}))
        L.append("## 8. Recommendations\n\n" + md_table(acts, 15))
    L.append("## 9. Conclusion")
    L.append((conclusions.strip() or "Findings above should be validated against Zeek/Suricata logs and "
              "packet captures before containment actions are applied.") + "\n")
    L.append("## 10. Limitations\n- Models were trained on benchmark datasets; real networks differ, so "
             "thresholds need tuning.\n- Flow-level features cannot inspect encrypted payloads.\n"
             "- Isolation Forest anomalies are leads, not confirmed attacks.\n")
    return "\n".join(L)


def to_html(md_text: str):
    import markdown
    body = markdown.markdown(md_text, extensions=["tables"])
    css = ("body{font-family:Segoe UI,Arial,sans-serif;max-width:960px;margin:2em auto;line-height:1.5;color:#222}"
           "table{border-collapse:collapse;margin:1em 0}td,th{border:1px solid #ccc;padding:4px 8px;font-size:13px}"
           "th{background:#1f2937;color:#fff}h1{border-bottom:3px solid #1f2937}h2{color:#1f2937}")
    return f"<html><head><meta charset='utf-8'><style>{css}</style></head><body>{body}</body></html>"
