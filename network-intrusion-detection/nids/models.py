"""Module 3 - machine-learning intrusion detection.

Supervised : Logistic Regression (baseline), Decision Tree (interpretable), Random Forest.
Multi-class: Random Forest identifies WHICH attack type it is.
Unsupervised: Isolation Forest trained on NORMAL traffic only -> catches unseen ("zero-day") behaviour.
Hybrid     : Random Forest OR Isolation Forest flags a flow.
"""
import time
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (accuracy_score, classification_report, confusion_matrix,
                             f1_score, precision_score, recall_score, roc_auc_score, roc_curve)
from sklearn.tree import DecisionTreeClassifier, export_text

from .config import MODEL_DIR, NORMAL, UNKNOWN_ANOMALY
from .preprocess import build_features

MODEL_NAMES = ["Logistic Regression", "Decision Tree", "Random Forest", "Isolation Forest",
               "Hybrid (RF + Isolation Forest)"]


def binary_metrics(y_true, y_pred, y_score=None):
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred, labels=[0, 1]).ravel()
    m = dict(
        Accuracy=accuracy_score(y_true, y_pred),
        Precision=precision_score(y_true, y_pred, zero_division=0),
        Recall=recall_score(y_true, y_pred, zero_division=0),
        F1=f1_score(y_true, y_pred, zero_division=0),
        FPR=fp / (fp + tn) if (fp + tn) else 0.0,
        FNR=fn / (fn + tp) if (fn + tp) else 0.0,
        TP=int(tp), FP=int(fp), TN=int(tn), FN=int(fn),
    )
    try:
        m["ROC_AUC"] = roc_auc_score(y_true, y_score) if y_score is not None else np.nan
    except ValueError:
        m["ROC_AUC"] = np.nan
    return m


def _sigmoid(z):
    return 1.0 / (1.0 + np.exp(-np.clip(z, -30, 30)))


def train_all(split, rf_trees=150, rf_depth=None, dt_depth=12, iso_trees=200,
              target_fpr=0.05, seed=42, progress=None):
    """Train every model, evaluate on validation + test, return a serialisable bundle."""
    say = progress or (lambda *_: None)
    Xtr, ytr, ybtr = split["X_train"], split["y_train"], split["yb_train"]
    models, times = {}, {}

    def fit(name, est, y):
        say(f"Training {name} ...")
        t = time.time()
        est.fit(Xtr, y)
        times[name] = round(time.time() - t, 2)
        return est

    models["Logistic Regression"] = fit("Logistic Regression", LogisticRegression(
        max_iter=500, class_weight="balanced", random_state=seed), ybtr)
    models["Decision Tree"] = fit("Decision Tree", DecisionTreeClassifier(
        max_depth=dt_depth, class_weight="balanced", random_state=seed), ybtr)
    models["Random Forest"] = fit("Random Forest", RandomForestClassifier(
        n_estimators=rf_trees, max_depth=rf_depth, class_weight="balanced_subsample",
        n_jobs=-1, random_state=seed), ybtr)
    rf_multi = fit("Random Forest (multi-class)", RandomForestClassifier(
        n_estimators=rf_trees, max_depth=rf_depth, class_weight="balanced_subsample",
        n_jobs=-1, random_state=seed), ytr)

    say("Training Isolation Forest on normal traffic only ...")
    t = time.time()
    iso = IsolationForest(n_estimators=iso_trees, contamination="auto", n_jobs=-1, random_state=seed)
    iso.fit(Xtr[ybtr == 0])
    times["Isolation Forest"] = round(time.time() - t, 2)
    # threshold from NORMAL validation traffic only: no attack labels needed
    s_val = -iso.score_samples(split["X_val"])
    normal_val = s_val[split["yb_val"] == 0]
    thr = float(np.quantile(normal_val, 1 - target_fpr))
    sigma = float(normal_val.std() + 1e-9)
    iso_info = dict(threshold=thr, sigma=sigma, target_fpr=target_fpr)

    bundle = dict(models=models, rf_multi=rf_multi, iso=iso, iso_info=iso_info,
                  prep=split["prep"], feature_cols=split["feature_cols"], extended=split["extended"],
                  classes=list(rf_multi.classes_), merged_classes=split["merged_classes"],
                  train_times=times, sizes=split["sizes"])

    rows, roc, cms = [], {}, {}
    for part in ("val", "test"):
        X, yb, ym = split[f"X_{part}"], split[f"yb_{part}"], split[f"y_{part}"]
        preds = {}
        for n, m in models.items():
            preds[n] = (m.predict(X), m.predict_proba(X)[:, 1])
        s = -iso.score_samples(X)
        preds["Isolation Forest"] = ((s > thr).astype(int), s)
        pm = rf_multi.predict_proba(X)
        p_att = 1 - pm[:, bundle["classes"].index(NORMAL)] if NORMAL in bundle["classes"] else pm.max(1)
        hyb = ((p_att > 0.5) | (s > thr)).astype(int)
        preds["Hybrid (RF + Isolation Forest)"] = (hyb, np.maximum(p_att, _sigmoid((s - thr) / sigma)))
        for n, (yp, sc) in preds.items():
            r = binary_metrics(yb, yp, sc)
            r.update(Model=n, Split=part)
            rows.append(r)
            if part == "test":
                f, t_, _ = roc_curve(yb, sc)
                roc[n] = (f, t_, r["ROC_AUC"])
                cms[n] = confusion_matrix(yb, yp, labels=[0, 1])
    metrics = pd.DataFrame(rows)[["Model", "Split", "Accuracy", "Precision", "Recall", "F1", "FPR",
                                  "FNR", "ROC_AUC", "TP", "FP", "TN", "FN"]]
    bundle["metrics"], bundle["roc"], bundle["cms"] = metrics, roc, cms

    # multi-class report on test
    ym = split["y_test"]
    yp = rf_multi.predict(split["X_test"])
    bundle["multiclass_report"] = pd.DataFrame(classification_report(ym, yp, output_dict=True,
                                                                    zero_division=0)).T
    labels = bundle["classes"]
    bundle["multiclass_cm"] = (labels, confusion_matrix(ym, yp, labels=labels))
    bundle["feature_importance"] = (pd.Series(models["Random Forest"].feature_importances_,
                                              index=split["feature_cols"]).sort_values(ascending=False))
    bundle["tree_rules"] = export_text(models["Decision Tree"], feature_names=split["feature_cols"],
                                       max_depth=4)
    return bundle


def score_flows(bundle, df, use_iso=True, rf_threshold=0.5):
    """Score flows -> adds final_category / final_conf / attack_prob / anomaly_score / flagged."""
    X = build_features(df, bundle["extended"], bundle["feature_cols"])
    Xt = bundle["prep"].transform(X)
    rf = bundle["rf_multi"]
    classes = list(rf.classes_)
    proba = rf.predict_proba(Xt)
    cat = np.array(classes)[proba.argmax(1)]
    conf = proba.max(1)
    p_att = 1 - proba[:, classes.index(NORMAL)] if NORMAL in classes else conf
    sup_flag = (p_att > rf_threshold)
    # if flagged by probability but argmax is Normal, use the most likely attack class
    if NORMAL in classes:
        pa = proba.copy()
        pa[:, classes.index(NORMAL)] = -1
        best_attack = np.array(classes)[pa.argmax(1)]
        cat = np.where(sup_flag, best_attack, cat)
        conf = np.where(sup_flag, p_att, conf)
    s = -bundle["iso"].score_samples(Xt)
    info = bundle["iso_info"]
    iso_flag = (s > info["threshold"]) if use_iso else np.zeros(len(s), bool)
    iso_conf = _sigmoid((s - info["threshold"]) / info["sigma"])
    final_cat = np.where(sup_flag, cat, np.where(iso_flag, UNKNOWN_ANOMALY, NORMAL))
    final_conf = np.where(sup_flag, conf, np.where(iso_flag, iso_conf, 1 - p_att))
    out = df.copy()
    out["final_category"] = final_cat
    out["final_conf"] = np.round(final_conf, 4)
    out["attack_prob"] = np.round(p_att, 4)
    out["anomaly_score"] = np.round(s, 4)
    out["flagged"] = (final_cat != NORMAL)
    return out


def save_bundle(bundle, name="nids_model.joblib"):
    path = MODEL_DIR / name
    joblib.dump(bundle, path, compress=3)
    return path


def load_bundle(name="nids_model.joblib"):
    path = MODEL_DIR / name
    return joblib.load(path) if path.exists() else None
