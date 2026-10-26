"""Command-line helper:  python -m nids.cli demo | selftest"""
import sys
import time

from . import alerts, data_loader, models, preprocess, report, synthetic
from .config import REPORT_DIR, DATA_DIR


def demo(n=60_000):
    print(f"[1/5] generating {n:,} synthetic flows")
    uni, _ = data_loader.standardize(synthetic.generate(n))
    print("[2/5] cleaning")
    df, rep = preprocess.clean(uni)
    print(f"      rows {rep['rows_loaded']:,} -> {rep['rows_final']:,} "
          f"(dups {rep['duplicates_removed']}, invalid {rep['invalid_rows_removed']})")
    print("[3/5] training models")
    split = preprocess.split_data(df)
    b = models.train_all(split, rf_trees=100, target_fpr=0.03, progress=lambda m: print("     ", m))
    models.save_bundle(b)
    m = b["metrics"]
    print(m[m.Split == "test"][["Model", "Accuracy", "Recall", "F1", "FPR"]].round(4).to_string(index=False))
    print("[4/5] raising alerts")
    scored = models.score_flows(b, split["meta_test"])
    a = alerts.build_alerts(scored)
    a = alerts.save_alerts(a, replace_source="ML")
    print(f"      {int(scored.flagged.sum()):,} suspicious flows -> {len(a)} alerts")
    print("[5/5] writing report")
    import joblib
    info = {"Source": "synthetic demo", "Rows": f"{len(df):,}"}
    joblib.dump((df, rep, info), DATA_DIR / "clean_dataset.joblib", compress=3)
    md = report.build_report(alerts.load_alerts(), b, info)
    p = REPORT_DIR / f"incident_report_{time.strftime('%Y%m%d_%H%M%S')}.md"
    p.write_text(md)
    print("done ->", p)


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "demo"
    if cmd in ("demo", "selftest"):
        demo(20_000 if cmd == "selftest" else 60_000)
    else:
        print(__doc__)
