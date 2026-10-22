# NSL-KDD: Data Prep and Baseline Findings

Source: `notebooks/nsl-kdd/scratch_randy.ipynb`. All numbers below come from runs in that notebook, evaluated on `KDDTest+`. Statements that come from background knowledge and were not verified against the data are marked **(unverified)**.

---

## 1. Data and preparation

### Files
- Train: `KDDTrain+.txt`, 125,973 rows, 43 columns, **no header row**.
- Test: `KDDTest+.txt`, 22,544 rows, same layout.
- Columns are 41 features, then `label` (attack type as text), then `difficulty` (integer).

### Column names
- Names were supplied manually via `names=` in `read_csv`, taken from the published KDD feature list.
- Verified against the header of `KDDTrain+.arff`. The check found one error: column 30 is **`srv_diff_host_rate`** (it had been entered as `srv_diff_srv_rate`). The other 40 feature names matched in order. The ARFF calls the label column `class`; that is only a naming difference.

### Cleaning checks
| Check | Train | Test |
|---|---|---|
| Null values | 0 | 0 |
| Duplicate rows | 0 | 0 |
| Test-only categorical values lost by `reindex` | n/a | none |

### Transformations
- Dropped `num_outbound_cmds` (constant, all zeros).
- Dropped `difficulty` (a score attached to the dataset's labels, not available to a detector at prediction time).
- One-hot encoded `protocol_type` (3 values), `service` (70) and `flag` (11), which adds 84 columns.
- Final feature matrix is **121 columns** (37 numeric + 84 one-hot). The test matrix was reindexed to the training columns (`reindex(columns=X.columns, fill_value=0)`).
- Binary target `is_attack = (label != "normal")`.
- No scaling was applied. Random forest and gradient boosting do not need it. Logistic regression or a neural network would (fit the scaler on train only, e.g. in a sklearn `Pipeline`).

```python
cols = [...]  # 43 names, with cols[30] = "srv_diff_host_rate"
df = pd.read_csv("KDDTrain+.txt", header=None, names=cols)
df["is_attack"] = (df["label"] != "normal").astype(int)
df = df.drop(columns=["num_outbound_cmds", "difficulty"], errors="ignore")
X = pd.get_dummies(df.drop(columns=["label", "is_attack"]),
                   columns=["protocol_type", "service", "flag"])
y = df["is_attack"]

test = pd.read_csv("KDDTest+.txt", header=None, names=cols)
test["is_attack"] = (test["label"] != "normal").astype(int)
test = test.drop(columns=["num_outbound_cmds", "difficulty"])
X_test = pd.get_dummies(test.drop(columns=["label", "is_attack"]),
                        columns=["protocol_type", "service", "flag"])
X_test = X_test.reindex(columns=X.columns, fill_value=0)
y_test = test["is_attack"]
```

---

## 2. Class balance

- Train: 53.5% normal, 46.5% attack. Test: 43.1% normal (9,711), 56.9% attack (12,833).
- Training has 23 labels. The largest are `normal` (67,343) and `neptune` (41,214). Twelve labels have fewer than 60 rows, for example `guess_passwd` 53, `warezmaster` 20, `rootkit` 10, `spy` 2.
- 17 attack types appear **only in the test set**: `apache2`, `httptunnel`, `mailbomb`, `mscan`, `named`, `processtable`, `ps`, `saint`, `sendmail`, `snmpgetattack`, `snmpguess`, `sqlattack`, `udpstorm`, `worm`, `xlock`, `xsnoop`, `xterm`. They cover 3,750 test rows (about 29% of test attacks).

---

## 3. Baseline: random forest

Settings: `RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1)`, binary target, default 0.5 threshold.

| | Precision | Recall | F1 | Support |
|---|---|---|---|---|
| normal | 0.66 | 0.97 | 0.79 | 9,711 |
| attack | 0.97 | 0.63 | 0.76 | 12,833 |

Accuracy 0.78. Confusion matrix: 9,452 normal passed, 259 false alarms, **4,782 attacks labelled normal**, 8,051 attacks caught.

Accuracy alone hides the problem. Attack recall is what matters for a detector.

### Where the misses come from (at threshold 0.5)

| Group | Test attacks | Recall | Approx. missed |
|---|---|---|---|
| Seen in training | 9,083 | 0.76 | ~2,140 |
| Unseen (test-only types) | 3,750 | 0.30 | ~2,640 |

- Seen-type misses are concentrated in two R2L attacks: `guess_passwd` (1,231 of 1,231 missed; 53 training rows) and `warezmaster` (838 of 944 missed; 20 training rows). Together they are about 97% of the seen-type misses.
- Common attacks are handled well: `neptune` 99.96% recall (4,657 rows), `back` 97%, `pod` 93%.
- Unseen types with zero or near-zero recall at 0.5: `mailbomb` (293 rows), `snmpguess` (331), `snmpgetattack` (178), `processtable` (685, 1%), `httptunnel` (133, 2%), `sendmail`, `xlock`, `worm`.

---

## 4. Things that did not help

| Attempt | Result |
|---|---|
| Binary RF with `class_weight="balanced_subsample"` | No change: accuracy 0.78, attack recall 0.63. `warezmaster` recall 0.11 to 0.18, `guess_passwd` still 0. The binary classes are already near 50/50, so the weights do almost nothing. |
| 23-class RF with `class_weight="balanced_subsample"`, collapsed to normal vs attack | Worse: attack recall 0.57, accuracy 0.75, normal precision 0.63. `warezmaster` 0.1%, `guess_passwd` 0. |

---

## 5. Lowering the decision threshold (random forest)

The model gives many missed attacks a low but non-zero probability, so the default 0.5 cutoff throws them away.

| Threshold | Attack recall | False alarms | False alarms as % of normal |
|---|---|---|---|
| 0.5 | 0.627 | 259 | 2.7% |
| 0.4 | 0.664 | 280 | 2.9% |
| 0.3 | 0.702 | 304 | 3.1% |
| 0.2 | 0.757 | 701 | 7.2% |
| 0.1 | 0.853 | 931 | 9.6% |
| 0.05 | 0.905 | 996 | 10.3% |
| 0.02 | 0.949 | 1,120 | 11.5% |

- `guess_passwd` probabilities: mean 0.067, median 0.04, max 0.32. It carries a weak signal the default cutoff discards.
- Still missed at threshold 0.1 (about 1,890 attacks): `guess_passwd` 1,000, `mailbomb` 254, `warezmaster` 197, `snmpguess` 185, `snmpgetattack` 178. Those five are about 96% of the remaining misses. `httptunnel`, `apache2`, `mscan` and `processtable` are now mostly caught.
- Random forest probabilities with 100 trees are multiples of 0.01, so very low thresholds mean "a few trees voted attack". More trees would give finer scores.

---

## 6. Model comparison

Same `X`, `y`, `X_test`, `y_test` for all models. Random forest as above; gradient boosting is `HistGradientBoostingClassifier(random_state=42)`.

AUC: RF 0.958, HGB 0.959, rank-average blend 0.965.

Recall at a fixed false alarm budget (read from each model's ROC curve):

| False alarms | % of normal | RF | HGB | Blend |
|---|---|---|---|---|
| 300 | 3.1% | 0.696 | **0.759** | 0.724 |
| 500 | 5.1% | 0.734 | **0.806** | 0.765 |
| 750 | 7.7% | 0.757 | **0.816** | 0.802 |
| 1,000 | 10.3% | **0.905** | 0.860 | 0.889 |
| 1,500 | 15.4% | **0.985** | 0.902 | 0.986 |

- Gradient boosting is the better detector up to roughly 750 false alarms. The random forest overtakes it at about 1,000, where it shows a sharp jump (0.757 to 0.905 between 750 and 1,000). The jump probably comes from the `guess_passwd` cluster, which was not confirmed.
- The blend lands between the two models at most budgets and only ties the forest at 1,500, so it is not worth the added complexity. Its higher AUC probably comes from the high false alarm end of the curve, which was not checked.
- The blend used `rankdata` over the test batch, so a connection's score depends on the other connections in the batch. It could not be used as-is on live traffic.
- Gradient boosting's useful thresholds are tiny (0.07 down to 0.0008), so a threshold sweep from 0.5 to 0.02 only shows the start of its curve.

---

## 7. Caveats and limitations

- **Thresholds were chosen by looking at the test set**, so the recall figures above are optimistic. Report the trade-off table, or fix a false alarm budget in advance and report the recall at that budget. A validation split from the training data would not help because it has no unseen attack types.
- **Base rate:** the test set is 43% normal traffic. A real network is overwhelmingly normal, so a 3 to 10% false alarm rate would produce far more alerts than this evaluation shows.
- **Part of the gap is the data itself.** `KDDTest+` contains attack types absent from training and several attacks with very few training rows (`guess_passwd` 53 training rows vs 1,231 in test). No tuning of these models closes that, which is a finding for the report.
- **(unverified)** NSL-KDD was built by removing duplicate records from KDD'99. The zero-duplicate result here is consistent with that.
- **(unverified)** The SNMP and mail attacks (`snmpguess`, `snmpgetattack`, `mailbomb`) may look like legitimate traffic at the level of connection statistics, which could explain why every model misses them.

---

## 8. Corrections made along the way

- Column 30 was `srv_diff_srv_rate`; the correct name is `srv_diff_host_rate` (caught by the ARFF check).
- I first expected unseen attack types to be the main cause of missed attacks. The seen/unseen split showed seen types contribute about 45% at threshold 0.5, mostly `guess_passwd` and `warezmaster`.
- I first expected class weighting to help the rare attacks; it did not (section 4).
- I first said unseen attacks could not be recovered by tuning; lowering the threshold recovered many of them (section 5).
- I first said gradient boosting gives smoother probabilities and stops improving at low thresholds; its probabilities are sharper and its useful thresholds are much lower (section 6).

---

## 9. Suggested next steps

1. Agree on the preprocessing and evaluation rule across the team: same columns, same encoding, evaluate on `KDDTest+`, report attack recall alongside accuracy and the false alarm count.
2. Decide on a false alarm budget, then pick the model by that budget (gradient boosting up to about 8% of normal traffic, random forest above).
3. Try the four-family multi-class version (DoS, Probe, R2L, U2R) to see which kinds of attack are being missed.
4. Port the preprocessing from the scratch notebook into the shared team notebook.
5. Optionally compare logistic regression and a neural network (both need scaling fitted on train only).
