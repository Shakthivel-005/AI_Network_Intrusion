"""Module 1 - data preparation: cleaning, encoding, scaling and leak-free splitting."""
import numpy as np
import pandas as pd
from sklearn.impute import SimpleImputer
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler

from .config import CORE_COLUMNS, CORE_NUMERIC, NORMAL, OTHER_ATTACK, PROTOCOLS
from .labels import normalize_label, to_family

_LOG_EXCLUDE = {"src_port", "dst_port"}


def clean(df: pd.DataFrame, group_families=True):
    """Return (clean_df, report). Every step is counted so the UI can show it."""
    rep = {"rows_loaded": len(df)}
    df = df.copy()

    # raw (original) label column can be named label or label_raw
    if "label_raw" not in df.columns:
        df["label_raw"] = df["label"] if "label" in df.columns else NORMAL
        df = df.drop(columns=[c for c in ["label"] if c in df.columns])
    rep["raw_label_values"] = int(df["label_raw"].nunique())

    num_cols = df.select_dtypes(include=[np.number]).columns
    rep["missing_values"] = {c: int(v) for c, v in df.isna().sum().items() if v > 0}
    rep["inf_values"] = int(np.isinf(df[num_cols]).sum().sum())
    df[num_cols] = df[num_cols].replace([np.inf, -np.inf], np.nan)

    # impossible values -> invalid rows
    bad = pd.Series(False, index=df.index)
    for c in ["flow_duration", "packet_count", "byte_count"]:
        if c in df:
            bad |= df[c] < 0
    for c in ["src_port", "dst_port"]:
        if c in df:
            bad |= (df[c] < 0) | (df[c] > 65535)
    if "packet_count" in df:
        bad |= df["packet_count"] == 0
    rep["invalid_rows_removed"] = int(bad.sum())
    df = df[~bad]

    # label normalisation
    df["category_detail"] = df["label_raw"].map(normalize_label)
    df["category"] = df["category_detail"].map(to_family) if group_families else df["category_detail"]
    rep["label_mapping"] = (df.groupby(["label_raw", "category"]).size()
                            .reset_index(name="rows").astype({"label_raw": str}))

    # rows with no label-relevant info
    before = len(df)
    df = df.dropna(subset=["flow_duration", "packet_count", "byte_count"], how="all")
    rep["empty_rows_removed"] = before - len(df)

    # duplicates (ignore the bookkeeping columns)
    keys = [c for c in df.columns if c not in ("label_raw", "source_file")]
    before = len(df)
    df = df.drop_duplicates(subset=keys)
    rep["duplicates_removed"] = before - len(df)

    df["is_attack"] = (df["category"] != NORMAL).astype(int)
    df["protocol"] = df["protocol"].astype(str).str.upper()
    df["protocol_group"] = np.where(df["protocol"].isin(PROTOCOLS[:3]), df["protocol"], "OTHER")
    df = df.sort_values("timestamp").reset_index(drop=True)

    rep["rows_final"] = len(df)
    vc = df["category"].value_counts()
    rep["class_counts"] = vc.to_dict()
    n_norm, n_att = int((df.is_attack == 0).sum()), int(df.is_attack.sum())
    rep["normal_rows"], rep["attack_rows"] = n_norm, n_att
    rep["imbalance_ratio"] = round(max(n_norm, n_att) / max(1, min(n_norm, n_att)), 2)
    return df, rep


# ------------------------------------------------------------------ features
def build_features(df: pd.DataFrame, extended=False, feature_cols=None):
    """Numeric feature matrix. Protocol is one-hot encoded; heavy-tailed values are log-scaled."""
    X = pd.DataFrame(index=df.index)
    dur = pd.to_numeric(df["flow_duration"], errors="coerce")
    pk = pd.to_numeric(df["packet_count"], errors="coerce")
    by = pd.to_numeric(df["byte_count"], errors="coerce")
    X["flow_duration"] = dur
    X["packet_count"] = pk
    X["byte_count"] = by
    rate = pd.to_numeric(df["flow_rate"], errors="coerce") if "flow_rate" in df else by / dur.replace(0, np.nan)
    X["flow_rate"] = rate
    X["packet_rate"] = pk / dur.replace(0, np.nan)
    X["avg_packet_size"] = by / pk.replace(0, np.nan)
    X["src_port"] = pd.to_numeric(df["src_port"], errors="coerce")
    X["dst_port"] = pd.to_numeric(df["dst_port"], errors="coerce")
    grp = df["protocol_group"] if "protocol_group" in df else \
        df["protocol"].astype(str).str.upper().where(lambda s: s.isin(PROTOCOLS[:3]), "OTHER")
    for p in PROTOCOLS:
        X[f"proto_{p}"] = (grp == p).astype(float)
    if extended:
        for c in df.columns:
            if c.startswith("x_"):
                X[c] = pd.to_numeric(df[c], errors="coerce")
    X = X.replace([np.inf, -np.inf], np.nan)
    for c in X.columns:
        if c.startswith("proto_") or c in _LOG_EXCLUDE:
            continue
        X[c] = np.sign(X[c]) * np.log1p(np.abs(X[c]))
    if feature_cols is not None:
        X = X.reindex(columns=feature_cols, fill_value=0.0)
    return X


def make_preprocessor():
    return Pipeline([("impute", SimpleImputer(strategy="median")), ("scale", StandardScaler())])


def merge_rare(y: pd.Series, min_count=30):
    """Classes too small to stratify are merged into 'Other Attack'."""
    vc = y.value_counts()
    rare = vc[(vc < min_count) & (vc.index != NORMAL)].index
    return y.where(~y.isin(rare), OTHER_ATTACK), list(rare)


def split_data(df, extended=False, test_size=0.2, val_size=0.15, seed=42,
               max_train_rows=250_000, min_class=30):
    """Stratified train/validation/test split. Scaling is fitted on TRAIN only (no leakage)."""
    y_cat, merged = merge_rare(df["category"], min_class)
    X = build_features(df, extended=extended)
    idx = np.arange(len(df))
    tr, tmp = train_test_split(idx, test_size=test_size + val_size, stratify=y_cat, random_state=seed)
    rel = test_size / (test_size + val_size)
    va, te = train_test_split(tmp, test_size=rel, stratify=y_cat.iloc[tmp], random_state=seed)
    if len(tr) > max_train_rows:
        tr, _ = train_test_split(tr, train_size=max_train_rows, stratify=y_cat.iloc[tr], random_state=seed)

    prep = make_preprocessor().fit(X.iloc[tr])  # fit on train only
    T = lambda ix: prep.transform(X.iloc[ix])
    out = dict(
        prep=prep, feature_cols=list(X.columns), extended=extended, merged_classes=merged,
        X_train=T(tr), X_val=T(va), X_test=T(te),
        y_train=y_cat.iloc[tr].values, y_val=y_cat.iloc[va].values, y_test=y_cat.iloc[te].values,
        meta_train=df.iloc[tr], meta_val=df.iloc[va], meta_test=df.iloc[te],
    )
    for k in ("train", "val", "test"):
        out[f"yb_{k}"] = (out[f"y_{k}"] != NORMAL).astype(int)
    out["sizes"] = {"train": len(tr), "validation": len(va), "test": len(te)}
    return out
