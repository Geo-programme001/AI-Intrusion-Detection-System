# AI-Intrusion-Detection-System — Roadmap

Everyone works across all phases together — no fixed roles. This maps the build
order onto the folders already in the repo (`datasets/`, `models/`, `results/`,
`dashboard/`, `tests/`) and lists what to install on Ubuntu for each phase.

---

## 0. Base environment (do this first, once, on every machine)

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv git

git clone https://github.com/Geo-programme001/AI-Intrusion-Detection-System.git
cd AI-Intrusion-Detection-System

python3 -m venv .venv
source .venv/bin/activate

pip install -r requirements.txt
```

- `requirements.txt` already pins the Jupyter + scikit-learn/pandas/numpy stack
  the repo was scaffolded with.
- Docs: [Python venv](https://docs.python.org/3/library/venv.html) ·
  [pip](https://pip.pypa.io/en/stable/) ·
  [JupyterLab](https://jupyterlab.readthedocs.io/en/stable/)
- Launch notebooks with `jupyter lab` from inside the repo.

---

## 1. Finalize dataset & environment

Pick **one** dataset up front — everything downstream depends on its features
and labels. Three realistic options:

| Dataset | What it is | Get it | Docs |
|---|---|---|---|
| **CICIDS2017** *(recommended default)* | 2017 traffic capture, labelled flows (CSV) + raw PCAPs, 14+ attack types (DoS, brute force, botnet, DDoS, web attacks, infiltration) | [Official page (UNB/CIC)](https://www.unb.ca/cic/datasets/ids-2017.html) — request/download form | [Paper: Sharafaldin et al. 2018 (ICISSP)](https://www.unb.ca/cic/datasets/ids-2017.html) |
| **NSL-KDD** | Cleaned-up successor to KDD Cup 99, smaller and easier to get started with, but older traffic patterns | [Official page (UNB/CIC)](https://www.unb.ca/cic/datasets/nsl.html) or [Kaggle mirror](https://www.kaggle.com/datasets/hassan06/nslkdd) | Tavallaee et al., *"A Detailed Analysis of the KDD CUP 99 Data Set"* |
| **UNSW-NB15** | 2015 hybrid real+synthetic traffic, 49 features, 9 attack categories | [Official page (UNSW)](https://research.unsw.edu.au/node/134656) | Moustafa & Slay, MilCIS 2015 |

**Recommendation:** CICIDS2017 — it's the most cited/current of the three, ships
pre-labelled flow CSVs (so you don't have to build feature extraction from raw
PCAPs to get started), and its scale (2.8M+ records) gives believable numbers
for a report.

Download the CSVs (`MachineLearningCSV.zip` / `GeneratedLabelledFlows.zip`) and
put them under `datasets/raw/`.

No extra software needed beyond the base environment for this phase — the CSVs
load straight into pandas.

---

## 2. EDA & cleaning → `datasets/processed/`

Work in a notebook (`jupyter lab`). Tools you already have via `requirements.txt`:
`pandas`, `numpy`, `matplotlib`, `seaborn`.

- Check class balance (`df['Label'].value_counts()`), missing/`inf` values
  (CICIDS2017 is known to have some `NaN`/`Infinity` rows), and column meanings.
- Docs: [pandas](https://pandas.pydata.org/docs/) ·
  [seaborn](https://seaborn.pydata.org/) ·
  CICIDS2017's own `TrafficLabelling` column descriptions (in the dataset's
  accompanying documentation from the official page above).
- Write the cleaned dataframe out (e.g. `to_csv` or `to_parquet`) into
  `datasets/processed/`.

---

## 3. Feature engineering

Still pandas/scikit-learn, no new installs.

- Encode categoricals (`OneHotEncoder` / `pd.get_dummies`), scale numerics
  (`StandardScaler`/`MinMaxScaler`), handle class imbalance.
- For imbalance, consider adding `imbalanced-learn` (SMOTE etc.) — not in
  `requirements.txt` yet:
  ```bash
  pip install imbalanced-learn
  pip freeze > requirements.txt   # keep the file in sync
  ```
  Docs: [imbalanced-learn](https://imbalanced-learn.org/stable/)
- Save the train/test split (e.g. with `joblib.dump` or as CSVs) so it's a
  shared, reusable artifact rather than something everyone re-generates
  slightly differently.

---

## 4. Baseline modeling → `models/`

All in scikit-learn, already installed.

- Train Logistic Regression, Decision Tree, Random Forest as a first pass.
- Docs: [scikit-learn: supervised learning](https://scikit-learn.org/stable/supervised_learning.html) ·
  [`RandomForestClassifier`](https://scikit-learn.org/stable/modules/generated/sklearn.ensemble.RandomForestClassifier.html)
- Save trained models with `joblib`:
  ```python
  import joblib
  joblib.dump(model, "models/random_forest_v1.joblib")
  ```

---

## 5. Evaluation & experiment tracking → `results/`

- Metrics: `sklearn.metrics` — `classification_report`, `confusion_matrix`,
  `precision_recall_fscore_support`.
  Docs: [scikit-learn: model evaluation](https://scikit-learn.org/stable/modules/model_evaluation.html)
- Save each run's metrics (e.g. as JSON/CSV) under `results/experiments/`,
  plots (confusion matrix heatmaps, ROC curves via `matplotlib`/`seaborn`)
  under `results/figures/`.
- Optional upgrade if runs multiply fast: `pip install mlflow` for proper
  experiment tracking ([MLflow docs](https://mlflow.org/docs/latest/index.html)) —
  only worth it if you're running many model/hyperparameter combinations.

---

## 6. Detection pipeline

- Wrap the winning model in a small Python function/module:
  `features_in -> {prediction, confidence}`.
- Initially test it by replaying rows from the held-out test set rather than
  live traffic — that's enough to prove the pipeline end-to-end.
- If/when you want real traffic capture later:
  ```bash
  sudo apt install -y wireshark tshark
  pip install scapy
  ```
  Docs: [Wireshark docs](https://www.wireshark.org/docs/) ·
  [tshark man page](https://www.wireshark.org/docs/man-pages/tshark.html) ·
  [Scapy docs](https://scapy.readthedocs.io/en/latest/)
  (On Ubuntu, `apt install wireshark` will prompt "allow non-root users to
  capture packets" — say yes, then add your user: `sudo usermod -aG wireshark $USER`,
  then log out/in.)
  You'd also need `CICFlowMeter` (or similar) to turn captured packets into the
  same feature schema CICIDS2017 uses — that only matters if you go beyond
  dataset replay.

---

## 7. Backend & dashboard → `dashboard/`

```bash
pip install django djangorestframework
pip freeze > requirements.txt
django-admin startproject nids_dashboard dashboard
```

- Models: `Alert`, `NetworkEvent`, `Host`, `User` (or Django's built-in auth).
- Docs: [Django docs](https://docs.djangoproject.com/en/stable/) ·
  [Django REST Framework](https://www.django-rest-framework.org/) ·
  [Django auth system](https://docs.djangoproject.com/en/stable/topics/auth/)
- SQLite (Django's default) is fine to start — no extra DB install needed;
  switch to PostgreSQL later only if you need concurrent write throughput:
  ```bash
  sudo apt install -y postgresql postgresql-contrib
  pip install psycopg2-binary
  ```
  Docs: [PostgreSQL on Ubuntu](https://ubuntu.com/server/docs/install-and-configure-postgresql)
- Dashboard pages: overview stats, alert list, alert detail — plain Django
  templates are enough; add `django-crispy-forms` or a JS chart lib
  (e.g. Chart.js via CDN) only if you want nicer visuals.

---

## 8. Testing & integration → `tests/`

```bash
pip install pytest pytest-django
pip freeze > requirements.txt
```

- Unit tests: preprocessing functions, model inference wrapper.
- Integration tests: API endpoint that receives an alert and stores it.
- Docs: [pytest](https://docs.pytest.org/en/stable/) ·
  [pytest-django](https://pytest-django.readthedocs.io/en/latest/)
- Finish with one end-to-end run: replay test-set rows through the pipeline →
  alert posted to the API → confirm it renders on the dashboard.

---

## Keeping `requirements.txt` current

Every time you `pip install` something new for the project, run
`pip freeze > requirements.txt` and commit it, so the base environment step
at the top of this file stays accurate for teammates cloning fresh.
