# 🛡️ AI-Based Network Intrusion Detection & Security Monitoring System

A SOC-style project for **Kali Linux (VMware)**: network-flow analysis, machine-learning attack detection,
alert management and a full GUI dashboard - installed and started with one command.

| | |
|---|---|
| Language / libs | Python 3 · Pandas · NumPy · Scikit-learn · Plotly |
| GUI | Streamlit (opens in the browser at `http://127.0.0.1:8501`) |
| Security tools | Wireshark/tshark (capture), Suricata (signatures), Zeek (flow logs) |
| Datasets | CIC-IDS2017, CSE-CIC-IDS2018, UNSW-NB15 (+ built-in synthetic generator for instant demo) |
| Models | Logistic Regression, Decision Tree, Random Forest, Isolation Forest, **Hybrid RF + IF** |

---------------------------------------------------------------------------------------------------

## 1. VMware + Kali preparation (once)

1. Kali VM: **≥ 4 GB RAM, 2+ CPUs, 40 GB disk** (8 GB RAM if you use full CIC-IDS2017).
2. VM network adapter: **NAT** is enough for installing and for the datasets. For a lab with a victim VM
   (e.g. Metasploitable) use **Host-only / custom VMnet** and put both VMs on it.
3. Inside Kali:
```bash
sudo apt update && sudo apt install -y git
```

## 2. Install - like any GitHub tool

### Option A - `git clone` (the normal way)
Put this folder on your GitHub (see §7), then on Kali:
```bash
git clone https://github.com/<your-username>/network-intrusion-detection.git
cd network-intrusion-detection
sudo ./install.sh
nids-gui
```

### Option B - apt-style `.deb` package
```bash
sudo apt install ./network-intrusion-detection_1.0.0_all.deb
nids-gui
```
> A bare `sudo apt install network-intrusion-detection` only works if the package sits in an apt repository.
> Installing the local `.deb` with `apt` is the standard equivalent (apt resolves the dependencies for you).
> Rebuild the `.deb` any time with `bash packaging/build_deb.sh`.

### Option C - no installation (developer mode)
```bash
cd network-intrusion-detection && ./run.sh
```

What the installer does: installs Python + venv, **tshark/Wireshark, Suricata, nmap** (Zeek if your repo has it),
creates `/opt/nids` with its own virtual environment (so Kali's "externally-managed-environment" error never
appears), installs `nids-gui` into `/usr/local/bin`, adds a menu entry, and adds you to the `wireshark` group
(log out/in once for live capture).

## 3. First run (2 minutes, no dataset needed)

```bash
nids-gui          # opens the dashboard
```
On **🏠 SOC Overview** click **🚀 Run full demo pipeline**. It generates traffic, cleans it, trains all models, scores
unseen test data and raises alerts. Then explore every page. (`nids-gui demo` does the same without the GUI.)

## 4. Using the real datasets

Download (free, manual):
* CIC-IDS2017 - https://www.unb.ca/cic/datasets/ids-2017.html → use the **TrafficLabelling** CSVs (they contain IPs and timestamps)
* CSE-CIC-IDS2018 - https://www.unb.ca/cic/datasets/ids-2018.html
* UNSW-NB15 - https://research.unsw.edu.au/projects/unsw-nb15-dataset → `UNSW_NB15_training-set.csv`

```bash
mkdir -p ~/datasets && mv ~/Downloads/*.csv ~/datasets/
```
In **📥 Data Preparation → Folder on this machine**, pick files, set *sample fraction* (e.g. 0.2) and *max rows*
(300 000 is comfortable in 4-8 GB RAM), click **Load files**. Column names, units (µs→s), protocol numbers,
corrupted labels (`Web Attack � Brute Force`), `inf`/NaN and duplicates are handled automatically.
Datasets without IPs/timestamps (UNSW training-set) get replay timestamps and a visible warning.

## 5. What each page does (maps to the project modules)

| Page | Requirement covered |
|---|---|
| 📥 Data Preparation | Module 1: import, dtypes, missing values, duplicates, invalid values, label fixing, protocol encoding, scaling, class imbalance, **leak-free stratified train/val/test split** |
| 🔎 Exploratory Analysis | Module 2: normal vs malicious, attack frequency, protocol volume, duration, packet/byte anomalies, traffic over time, port distributions, correlation heat-map, scanning-host analytics |
| 🤖 ML Detection | Module 3: LR, DT, RF, Isolation Forest (trained on **normal only**), hybrid; accuracy, precision, recall, F1, **false-positive rate**, ROC, confusion matrices, multi-class attack classifier, feature importance, readable Decision-Tree rules |
| 🚨 Alerts | Module 4: attack-type classification, `ALT-1001…` IDs, timestamps, **Low/Medium/High/Critical** severity, confidence, **New/Investigating/Resolved** status, editable analyst notes, bulk actions, evidence flows, CSV export; flows are **grouped into incidents** to cut alert fatigue |
| 📡 Live Monitoring | tshark live capture, PCAP analysis, Zeek `conn.log` scoring, Suricata `eve.json` import, scoring any CSV |
| 📝 Incident Report | Auto-generated investigation report (Markdown/HTML→PDF) |

**Severity logic:** base level by attack type (Bot/DDoS → Critical, DoS/Brute-force/Web → High, Port-scan → Medium …),
lowered when confidence < 60 %, raised for large campaigns or repeat offenders.

**Design choices worth explaining in a viva:** hybrid supervised + unsupervised detection (known + unknown attacks);
FPR reported next to recall; class-weighted learning for imbalance; imputer/scaler fitted on train only; duplicates
removed before the split; grouped alerts instead of one-alert-per-flow; "core" feature set so the same model scores
live Zeek/tshark traffic, "extended" feature set for best accuracy on full CIC/UNSW columns.

## 6. Safe lab test with real traffic (only your own VMs!)

```bash
# Kali -> victim VM (host-only network).  Start a capture in Live Monitoring, then run ONE of:
nmap -sS -p 1-5000 <victim-ip>                     # port scan
hydra -l test -P /usr/share/wordlists/rockyou.txt -t 4 ssh://<victim-ip>   # brute-force pattern
sudo hping3 -S --flood -p 80 <victim-ip>           # SYN-flood pattern (keep it a few seconds)
```
Train on the **core feature set** first, then click *Capture & analyse*. Never scan or flood networks you do not own.

## 7. Publishing to GitHub (so you can `git clone` it)

```bash
cd network-intrusion-detection
git init && git add . && git commit -m "AI-NIDS v1.0"
git branch -M main
git remote add origin https://github.com/<your-username>/network-intrusion-detection.git
git push -u origin main
```

## 8. Troubleshooting

| Problem | Fix |
|---|---|
| `nids-gui: command not found` | Re-run `sudo ./install.sh`, open a new terminal |
| pip fails during install | Check internet (VM NAT), then `nids-gui --repair` |
| Browser doesn't open | Open `http://127.0.0.1:8501` manually |
| Capture "permission denied" | Log out/in (wireshark group) or `sudo -E nids-gui` |
| Out of memory on big CSVs | Lower *sample fraction* / *max rows*, add RAM to the VM |
| Suricata finds nothing | `sudo suricata-update` to download rules |
| Zeek missing | Optional - tshark flow engine works without it (install from docs.zeek.org if wanted) |
| Port already used | `NIDS_PORT=8600 nids-gui` |

Uninstall: `sudo ./uninstall.sh` (your data in `~/.nids` is kept).

## 9. Project layout

```
app.py                 Streamlit GUI (all pages)
nids/data_loader.py    CIC-IDS2017 / 2018 / UNSW-NB15 -> unified schema
nids/preprocess.py     cleaning, features, scaling, leak-free split
nids/labels.py         label normalisation & attack families
nids/eda.py            Module 2 charts
nids/models.py         LR / DT / RF / Isolation Forest / hybrid + metrics
nids/alerts.py         grouping, severity, SQLite alert store
nids/behavior.py       per-host scan/flood analytics
nids/live.py           tshark / Zeek / Suricata integration
nids/report.py         incident report
nids/synthetic.py      demo traffic generator
install.sh · run.sh · uninstall.sh · packaging/ (launcher + .deb builder)
```

## 10. Honest limitations (put these in your report)
Benchmark datasets differ from real networks, so thresholds need re-tuning; flow features cannot inspect encrypted
payloads; Isolation Forest anomalies are leads, not proof; the synthetic data is for demonstration, so report final
accuracy numbers from the real datasets.
