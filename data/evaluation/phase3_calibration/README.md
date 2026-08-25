# Phase 3 Calibration Inputs

This directory records the provenance and contracts for the supervisor-required
threshold calibration. It intentionally does not contain raw URLs.

## Raw inputs

The project owner supplied these local files:

```text
data/raw/phase3_calibration/benign/tranco_top_1m.csv
data/raw/phase3_calibration/suspicious/phishtank_online_valid.csv
```

`data/raw/` is ignored by Git because the inputs are large and the PhishTank
feed may contain live malicious destinations. `source_manifest.json` locks the
exact local inputs by byte size and SHA-256 so later calibration can be traced
without committing active URLs.

The labels have intentionally different strength:

- `suspicious`: PhishTank marked the URL as verified phishing and online at the
  time of retrieval.
- `presumed_benign`: Tranco ranked the domain as popular. Popularity is useful
  calibration evidence but is not proof that a domain is always safe.

No URL in either input should be opened manually. Calibration code may parse
the files as data, but network-backed analysis belongs to the later calibration
commit and must record incomplete cases.

## Versioned contracts

`app/services/decision_policy.py` defines strict contracts for:

- source provenance;
- sampled records identified by source row and payload hash, without storing
  the raw URL in the committed contract;
- separate, stratified calibration and validation splits;
- the three ordered boundaries `T1/T2/T3`;
- suspicious benchmark `B` and agreement margin `D`;
- calibration counts and confusion-matrix metrics;
- verdict floors and policy limitations; and
- the final calibration report.

## Provisional calibration result

Run the bounded calibration with the project environment and local url.vet:

```powershell
conda activate qrcode
$env:QR_URLVET_VERSION="urlvet-556c7aa3f5bb"
python scripts\calibrate_phase3_policy.py
```

The script verifies both raw source hashes, selects 60 records with fixed seed
`5238`, and assigns 20 presumed-benign plus 20 suspicious records to the
calibration split and 10 plus 10 to validation. It stores an ignored local
cache under `data/processed/` so interrupted url.vet collection can resume. Use
`--retry-unavailable` to retry only missing url.vet scores or `--refresh` to
rescan every selected URL.

The committed generated files contain no URL payloads:

- `calibration_dataset.json` records source rows, labels, splits, and payload
  hashes;
- `calibration_observations.json` records the two scores, verdict, and analysis
  availability for each payload hash;
- `decision_policy.json` contains the selected versioned policy; and
- `reports/phase3_calibration_report.json` contains calibration and validation
  metrics, score distributions, methodology, versions, and limitations.

The selected `phase3-decision-policy-v1` is deliberately **provisional**:

| Parameter | Selected value | Evidence definition |
|---|---:|---|
| `T1` | 62 | Ceiling of the presumed-benign calibration combined-score third quartile |
| `T2` | 79 | The labelled suspicious benchmark `B` |
| `T3` | 100 | Ceiling of the suspicious calibration combined-score first quartile |
| `B` | 79 | Best safety-first candidate among integer values 1-99 |
| `D` | 1 | Rounded first quartile of absolute risk/judgement score differences, with minimum 1 |

The four exact intervals are `Low 0-<62`, `Medium 62-<79`, `High 79-<100`,
and `Dangerous 100`. The combined calibration prediction uses the more cautious
`max(risk_score, judgement_score)` and treats url.vet `Suspicious`, `Risky`, and
legacy-compatible `Malicious` verdicts as adverse evidence.

The evidence does not justify describing this policy as approved. Of 60 fixed
records, 50 obtained both scores: 7 url.vet analyses were complete, 43 were
partial, and 10 had no usable url.vet score within the bounded client request.
On the 16 validation records with both scores, the policy detected all 9
suspicious records but warned on 5 of 7 presumed-benign records: recall `100%`,
false-negative rate `0%`, and false-positive rate `71.4%`. Three of those five
warnings were driven by a url.vet `Suspicious` verdict despite both numeric
scores staying below `B`; two also had local LR scores above `97`. These are small-sample
observations, not population guarantees. The high false-positive rate shows
that the safety-first combination currently over-warns.

PhishTank is also both the suspicious-label source and a threat-intelligence
source used by url.vet. This report therefore demonstrates the integration and
its operating point; it is not independent external validation of url.vet.
The real suspicious QR-image evaluation required by the supervisor remains a
separate later commit.

This commit generates and documents the policy but does not change API or UI
decisions. Runtime integration begins only in the later two-score and conflict
handling commits.
