## Project Structure

```text
QR_Shield_V2/
├── app/
│   ├── main.py                       # FastAPI application and analysis endpoints
│   ├── schemas.py                    # API request and response schemas
│   ├── services/
│   │   ├── block_inspection.py       # Five-region QR tampering inspection
│   │   ├── checks.py                 # Common evidence-check structures
│   │   ├── denylist.py               # Local reputation lookup
│   │   ├── model_service.py          # Local URL risk-model inference
│   │   ├── payment_verification.py   # Payment payload parsing and comparison
│   │   ├── qr_decoder.py             # QR decoding: ZXing (pyzxing) primary, OpenCV fallback
│   │   ├── review_store.py           # Consented human-review queue
│   │   ├── url_features.py           # Local hostname and URL feature helpers
│   │   ├── url_vet_client.py         # Loopback-only HTTP client for url.vet
│   │   └── url_vet_check.py          # url.vet response-to-check adapter
│   └── ui/
│       ├── api_client.py             # Streamlit-to-FastAPI client
│       ├── presentation.py           # Student-facing result and error wording
│       └── streamlit_app.py          # English Streamlit interface
├── data/
│   ├── evaluation/e3_us1/           # Locked evidence-fusion scenarios
│   ├── processed/                   # Local denylist and merchant references
│   └── test_images/                 # Categorised manual and automated fixtures
│       ├── e1_us1_upload/
│       ├── e1_us2_risk/
│       ├── e1_us3_content/
│       ├── e2_us1_tampering/
│       ├── e2_us2_payment/
│       ├── e2_us3_isolation/
│       ├── e3_us1_evidence/
│       └── manual_demo/
├── models/                         # Versioned local model and metadata
├── reports/                        # Evaluation and reliability reports
├── scripts/                        # Startup, dataset generation and evaluation tools
├── tests/                          # API, service, UI and dataset regression tests
├── .streamlit/config.toml          # Streamlit runtime configuration
├── requirements.txt                # Python dependencies
└── README.md
```

## Environment

- Python 3.10
- Windows, macOS, or Linux
- No GPU is required.
- The application runs locally and does not require the original training
  dataset for normal use.
- URL QR risk analysis requires the separately self-hosted url.vet Docker
  service described below. Tests mock this dependency and do not require Docker.
- The Java runtime for the ZXing decoder is supplied by the `jdk4py` package
  (installed from `requirements.txt`), so no separate JDK install is needed. On
  first use ZXing downloads its `.jar` once into a local cache; afterwards
  decoding runs offline.

## Start the Project

From the project root, create and activate a virtual environment, install the
dependencies, then start the local API and Streamlit interface:

```bash
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS/Linux
source .venv/bin/activate

python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python scripts/start_demo.py --check
python scripts/start_demo.py
```

If the project-specific `qrcode` environment is already installed, activate it
through your environment manager before running the same commands:

```powershell
conda activate qrcode
python scripts/start_demo.py --check
python scripts/start_demo.py
```

Open the following local addresses after startup:

- Streamlit interface: <http://localhost:8501>
- FastAPI health check: <http://127.0.0.1:8000/health>
- API documentation: <http://127.0.0.1:8000/docs>

## url.vet Local Service

QR Shield uses a separately self-hosted instance of
[`abhizaik/urlvet`](https://github.com/abhizaik/urlvet) for explainable risk
analysis of supported web URLs. The service is outside this repository and is
licensed under AGPL-3.0. QR Shield calls its local REST API; it does not bundle
or modify the url.vet source code.

Start the url.vet Docker stack before analysing an HTTP/HTTPS QR code. The
default service address is `http://127.0.0.1:8080`:

```text
GET http://127.0.0.1:8080/health
GET http://127.0.0.1:8080/api/v1/analyze?url=<encoded-target>
```

The QR Shield client accepts these optional environment variables:

- `QR_URLVET_BASE_URL` — loopback HTTP base URL; defaults to
  `http://127.0.0.1:8080` and rejects non-loopback addresses.
- `QR_URLVET_VERSION` — version label recorded in `source_versions`;
  defaults to `urlvet-local`.

For a valid HTTP/HTTPS URL with a legal hostname, QR Shield sends the URL to
the local url.vet service. url.vet may inspect the destination and related
external evidence, so URL analysis is not entirely offline. QR Shield still
keeps the uploaded image in memory, does not retain it during ordinary
analysis, and never opens the decoded destination in the user's browser.

Only supported web URLs reach url.vet. Plain text, payment payloads, malformed
HTTP/HTTPS URLs, unsupported URI schemes such as `ftp:` or `mailto:`, and
structured non-web payloads such as WiFi strings and vCards receive a
`url_vet: not_applicable` check and are not sent to url.vet.

## Test Image Dataset

All uploadable test images are stored under `data/test_images` and grouped by
user story and scenario. The dataset includes supported and rejected uploads,
four suspicion-level examples, decoded-content cases, five-region tampering,
payment verification, isolation targets, and evidence-fusion scenarios.

See `data/test_images/README.md` and `data/test_images/manifest.json` for the
directory map, payloads, and expected outcomes. Regenerate the complete pack
with:

```bash
python scripts/generate_test_images.py
python scripts/generate_tampering_fixtures.py
python scripts/generate_demo_qr.py
```

# E1-US1: Upload and Scan a QR Image

**User story:** As a student, I want to upload or scan a QR image so that the
system can check it before opening the destination.

## Acceptance Criteria

### AC1: Upload, preview, and safe decoding

**Given** a valid PNG/JPG/JPEG QR image

**When** the user uploads it and selects Analyze

**Then** the system previews and decodes it without automatically opening the
destination.

### AC2: Invalid upload handling

**Given** an empty, damaged, unsupported, or over-5-MiB file

**When** it is submitted

**Then** the system rejects it with a clear, recoverable English error and does not
call the model.

### AC3: Independent consecutive analysis

**Given** one failed analysis

**When** the user submits a second valid image in the same session

**Then** the second analysis succeeds independently.

## Tasks

- E1-US1-T01 - Upload, preview, and explicit Analyze action
- E1-US1-T02 - Validate and decode the image in memory
- E1-US1-T03 - Recovery and continuous-session regression

Upload a QR image, preview it, and select **Analyze QR Code** to decode it
locally before visiting its destination. Decoded URLs remain untrusted text and
are never opened automatically.

## Implemented Features

- Upload PNG, JPG, and JPEG QR images through the Streamlit interface.
- Preview the selected image before analysis.
- Require an explicit **Analyze QR Code** action; selecting a file does not
  start analysis automatically.
- Validate the filename extension, actual PNG/JPEG content, file size (5 MiB),
  and image size (25 megapixels) before decoding.
- Decode QR content locally with ZXing (OpenCV fallback) and return the decoded
  text, content type, and image dimensions.
- Reject empty, damaged, unsupported, oversized, and non-QR images with
  recoverable plain-English UI errors.
- Keep decoded destinations inert: no HTTP request, DNS lookup, browser launch,
  redirect, or socket connection is made during QR decoding.

Direct camera capture is not implemented in this branch.

## How It Is Implemented

The Streamlit UI uses `st.file_uploader` to accept only PNG, JPG, and JPEG
files, renders an image preview, and sends image bytes to `POST /api/v1/analyze`
only after the user selects the Analyze button.

The FastAPI endpoint reads at most 5 MiB plus one byte. Oversized uploads are
rejected with HTTP 413 before QR decoding or URL-model inference. Other input
validation errors are rejected with HTTP 400 before any URL-model inference.

`app/services/qr_decoder.py` validates image bytes with Pillow, then decodes
with ZXing (via `pyzxing`) for robustness and falls back to OpenCV when ZXing is
unavailable. Only QR-family formats are accepted, so a 1D barcode accidentally
detected inside a distorted QR is ignored. ZXing decodes through a short-lived
private temporary image that is deleted immediately; the decoded URL is passed
as text only and is never fetched or opened.

# E1-US2: Risk Score and Level

**User story:** As a student who has scanned a QR code, I want to receive a
clear 0-100 risk score and an explicit suspicion level before visiting its URL,
so that I can make a safer decision quickly.

## Acceptance Criteria

### AC1: Score and level mapping

**Given** a URL QR code and a successful model analysis

**When** results are returned

**Then** the score is within 0-100 and the current versioned policy maps it to
Low suspicion (`0 <= score < 62`), Medium suspicion (`62 <= score < 79`),
High suspicion (`79 <= score < 100`), or Dangerous (`score = 100`).

### AC2: Incomplete assessment

**Given** a mandatory check fails, or both URL score sources provide no usable score

**When** the result is assembled

**Then** the UI shows Incomplete / Unable to Assess rather than Low. If exactly
one URL score source is usable, the UI shows a clearly labelled Partial result
with Low confidence and Review required instead of hiding that available score.

### AC3: Deterministic result

**Given** the same model version and input

**When** analysed repeatedly

**Then** the score and level are deterministic within the documented
tolerance.

## Tasks

- E1-US2-T01 - Score and level mapping
- E1-US2-T02 - Student-focused risk-result component
- E1-US2-T03 - Incomplete and failed-check state
- E1-US2-T04 - Threshold calibration and evidence report

Valid HTTP/HTTPS URL QR codes with a legal hostname are analysed by the
versioned, self-hosted url.vet service. The UI displays its 0-100 risk score,
the four-level Phase 3 suspicion policy, optional verdict, raw trust score, and
up to three reasons. If url.vet returns a usable score with incomplete
evidence, the API preserves that score, marks the URL assessment as `Partial`,
lowers confidence, and tells the user that the result requires review. If
url.vet returns no usable score, the local lexical judgement may still be
shown as a clearly labelled partial advisory result. Only when no usable URL
score remains, or another mandatory check fails, does the API return
`Incomplete`; it never invents a completed two-source conclusion.

## Implemented Features

- Analyse supported URL QR codes through the local url.vet service and map its
  risk score to 0-100.
- Map scores to four suspicion levels using the checked-in Phase 3 policy.
- Display clear English risk-score and risk-level results.
- Return url.vet's model name, version label, optional verdict and trust score,
  and up to three reasons.
- Preserve usable partial url.vet evidence and provide a clearly labelled local
  score fallback when url.vet is unavailable.
- Produce deterministic score and level results for the same input and model version.

## How It Is Implemented

`app/services/url_vet_client.py` sends only approved URL payloads to the
loopback url.vet service with a hard timeout and `trust_env=False`.
`app/services/url_vet_check.py` validates the response, maps its score to the
project's risk levels, and preserves verdict, trust score, reasons, and the
configured version label. For valid URLs, the retained local Logistic
Regression model also produces a secondary judgement score; it does not fetch
the destination or replace url.vet.

The API returns url.vet evidence and the local judgement to the Streamlit UI.
If url.vet is unavailable, the local judgement can be returned as
`analysis_status: "Partial"` with Low confidence, while a usable partial
url.vet response is retained alongside the local score. The UI explains that
the result is advisory and requires review. A complete two-source result is
never claimed when a mandatory source is missing.

## Testing

Run the complete automated regression suite with:

```bash
python -m unittest discover -s tests -p "test_*.py" -v
```

E1-US1 coverage includes:

- PNG and JPEG QR decoding.
- Empty, damaged, unsupported, renamed-image, oversized, over-pixel-limit, and
  non-QR image rejection.
- API responses for invalid uploads and oversized files.
- A regression test confirming invalid uploads are rejected before decoding
  completes.
- Consecutive upload isolation at API level, so one result does not leak into
  the next request.
- Safety tests that intercept DNS, HTTP, socket, and browser operations and
  confirm that the QR decoding path does not call them.

E1-US2 coverage includes deterministic score handling, Phase 3 boundary
mapping, model versioning, unavailable-source Incomplete handling, and lexical
URL feature extraction.

# E1-US3: Destination and Reasons

**User story:** As a user receiving a QR-code risk result, I want to see the
destination hostname and plain-language reasons for the warning, so that I can
understand the decision before acting.

## Acceptance Criteria

### AC1: Safe destination details

**Given** a successfully decoded HTTP/HTTPS QR code

**When** the result page opens

**Then** it separately shows the non-clickable decoded URL, normalized hostname,
and no more than three supported reasons.

### AC2: Traceable explanation

**Given** the response is generated by the configured URL analysis source

**When** the explanation is displayed

**Then** the API and UI identify the same reasons and exact source version.

### AC3: Unscored content

**Given** the decoded content is plain text or malformed as a URL

**When** displayed

**Then** the system clearly states that URL risk scoring was not performed.

## Tasks

- E1-US3-T01 - Display decoded content safely
- E1-US3-T02 - Parse and display hostname
- E1-US3-T03 - Traceable reasons and model version
- E1-US3-T04 - Explanation consistency tests

The API extracts the hostname locally from the decoded URL text without DNS
lookups. Supported URL QR codes receive up to three url.vet reasons, plus its
verdict and optional trust score. Plain-text, unsupported URI, structured
non-web, payment, and malformed URL QR content have no hostname and are marked
as not scored.

## Implemented Features

- Display decoded URL content as non-clickable text.
- Extract and display a normalized hostname without DNS resolution.
- Display no more than three plain-language url.vet reasons.
- Display the configured url.vet version and optional verdict/trust score.
- Mark non-web, unsupported, and malformed QR content as not scored.
- Keep the API explanation and UI explanation consistent.

## How It Is Implemented

`app/services/url_features.py` parses the decoded URL text locally and returns
a normalized hostname without opening, resolving, or requesting the URL.

`app/services/url_vet_check.py` returns the url.vet version, verdict, trust
score, and up to three reasons with every supported URL risk result. The API
passes these fields through to the Streamlit UI, which displays the hostname,
verdict, trust score, version, and reasons.

If the decoded content is not a supported HTTP(S) URL with a valid hostname,
the API does not call url.vet. It returns a `Not scored` status with a
`url_vet: not_applicable` boundary check, and the UI explains why URL risk
scoring was not performed.

# E2-US1: Five-Region QR Tampering Detection

**User story:** As a user scanning a public poster, I want the system to
inspect the centre and four corner blocks for hidden or overlaid malicious
content, so that a QR code that looks normal as a whole can still be flagged.

## Acceptance Criteria

### AC1: Separate five-region evidence

**Given** a clean and a labelled tampered QR image

**When** five-region analysis runs

**Then** the system returns separate centre and four-corner results and
identifies the labelled tampered region within the approved threshold.

### AC2: Insufficient-quality result

**Given** image quality is insufficient for a reliable decision

**When** analysis completes

**Then** the result is Incomplete with a reason and is never silently Clean.

### AC3: No automatic destination visit

**Given** any tampering analysis

**When** processing occurs

**Then** no decoded destination is automatically opened.

## Tasks

- E2-US1-T01 - Define and extract five ROIs
- E2-US1-T02 - Overlay and multi-code feature detection
- E2-US1-T03 - Tampering dataset and threshold evaluation
- E2-US1-T04 - Tampering API, UI, and regression

The system applies perspective correction to the localized QR code and inspects
the centre plus four corner regions. It returns region-level evidence and marks
unreadable or unlocalizable images as Incomplete rather than Clean.

## Implemented Features

- Extract the top-left, top-right, centre, bottom-left, and bottom-right
  regions after QR perspective correction.
- Return a separate status, black-module ratio, and nested-QR indicator for
  each region.
- Flag multiple detected QR codes and suspicious region anomalies for review.
- Return an Incomplete result with a reason when the QR regions cannot be read
  or localized.
- Provide a labelled clean/tampered fixture dataset and an evaluation report.
- Keep decoded destination content inert throughout tampering analysis.

## How It Is Implemented

`app/services/block_inspection.py` uses OpenCV to find the QR boundary, warp it
to a normalized grid, and calculate local evidence for five fixed regions. A
second decoded QR in a region or an out-of-range black-module ratio produces a
warning. Failed image decoding or QR localization returns an `incomplete`
status with a stable reason code.

The API includes this evidence in the analysis result, and the Streamlit UI
renders the five-region result without turning the decoded destination into a
link or visiting it.

## Testing

E2-US1 coverage includes clean and labelled tampered fixtures, region evidence,
multiple-QR and anomaly detection, incomplete image handling, safe processing,
and dataset-threshold evaluation. Run the dataset evaluation with:

```bash
python scripts/evaluate_tampering_fixtures.py
```

# E2-US2: Payment Tampering Detection

**User story:** As a student paying by QR code, I want the system to detect
when the payment amount or payee differs from the expected merchant
information, so that I am protected from payment fraud.

## Acceptance Criteria

### AC1: Explicit payment-field mismatches

**Given** a supported payment payload and a trusted expected value

**When** analysis compares amount, currency, and payee or merchant

**Then** every mismatch is explicitly identified before any payment action.

### AC2: Missing trusted reference

**Given** no trusted reference exists

**When** the user requests verification

**Then** the system reports Unverifiable and requests confirmation rather than
claiming a match.

### AC3: No payment action

**Given** any payment QR analysis

**When** results are shown

**Then** the system never initiates, authorizes, or redirects to payment.

## Tasks

- E2-US2-T01 - Payment payload parser and schema
- E2-US2-T02 - Trusted reference and user confirmation
- E2-US2-T03 - Field comparison and tampering rules
- E2-US2-T04 - Safe confirmation UI and tests

The system recognizes the local `QRSHIELD-PAY:v1` demonstration payload,
validates its fields, and compares it with a local trusted merchant reference.
It reports individual payee, amount, and currency mismatches. Missing merchant
references are Unverifiable and require the user to confirm the payee and
amount before paying.

## Implemented Features

- Parse a strict versioned payment payload containing merchant ID, payee ID,
  amount, and currency.
- Validate field names, duplicate fields, identifiers, monetary amounts, and
  three-letter currencies before comparison.
- Compare payee, amount, and currency independently against a local trusted
  merchant reference.
- Return explicit mismatch reason codes for every differing field.
- Return `Unverifiable` and a user-confirmation warning when no trusted
  merchant reference exists.
- Display only a masked payee identifier and never start, authorize, or
  redirect a payment.

## How It Is Implemented

`app/services/payment_verification.py` parses payment data locally and uses
`Decimal` for exact money comparisons. Trusted reference values are loaded from
`data/processed/merchant_references.csv`. The API returns the payment result as
structured data, including status, reason codes, and safe evidence; payment
payloads bypass URL-risk scoring.

The Streamlit UI displays a local verification result, masks the payee ID, and
shows a confirmation warning for an Unverifiable result. It contains no payment
link, gateway request, redirect, authorization, or payment initiation logic.

## Testing

E2-US2 coverage includes valid and malformed payload parsing, duplicate and
missing fields, payee/amount/currency mismatch reporting, unknown-reference
Unverifiable handling, API response structure, UI confirmation text, and the
assertion that payment QR analysis does not invoke URL-risk scoring.

# E2-US3: Safe Local Analysis Boundary

**User story:** As a cautious user, I want QR-code analysis to occur within a
safe isolation boundary without automatically opening the link, so that my
device is not exposed during analysis.

## Acceptance Criteria

### AC1: Local processing and controlled URL inspection

**Given** any decoded QR payload

**When** analysis runs

**Then** image processing, QR decoding, tampering inspection, payment
verification, and local denylist checks remain local; only a valid HTTP/HTTPS
URL may be sent to the loopback url.vet service, and the browser never opens
the destination automatically.

### AC2: Future remote-inspection policy

**Given** optional remote inspection is enabled in a later iteration

**When** the target resolves to a prohibited address or exceeds a resource
limit

**Then** inspection is blocked or terminated with a controlled Incomplete
result.

### AC3: Adversarial target isolation

**Given** an adversarial target attempts scripts, downloads, forms, or repeated
redirects

**When** analysed

**Then** prohibited actions remain disabled and the application does not crash.

## Tasks

- E2-US3-T01 - No-network lexical-analysis boundary
- E2-US3-T02 - SSRF, DNS, and redirect policy
- E2-US3-T03 - Resource-limited sandbox
- E2-US3-T04 - Adversarial isolation test suite

The application keeps image processing, QR decoding, tampering inspection,
payment verification, and local denylist checks local. A valid HTTP/HTTPS URL
with a legal hostname is the deliberate exception: it is sent to the
loopback-only url.vet client, whose service may perform outbound inspection.
All other payload types stay outside url.vet, and the decoded destination is
never opened by the browser.

## Implemented Features

- Keep decoded destinations as untrusted, non-clickable text throughout the
  decoding and result-rendering flow.
- Return a common check contract for block inspection, url.vet, local denylist,
  and payment verification.
- Aggregate checks into `assessment_outcome`, `analysis_status`, and failed
  check IDs.
- Return `Incomplete` rather than a low-risk conclusion when no usable URL score
  remains, or when another mandatory check cannot complete.
- Preserve a usable score from either url.vet or the local judgement model as a
  clearly labelled Partial result when the other URL score source is unavailable.
- Display local-check evidence and a Review required warning in the UI.
- Keep automated tests network-independent by mocking url.vet, and verify that
  the unsupported-content gate never calls it.

## How It Is Implemented

`app/services/checks.py` defines a shared check result structure containing a
check ID, status, summary, reason codes, and safe local evidence. Its cautious
aggregation policy keeps image inspection, denylist, payment, policy, and other
mandatory failures as `Incomplete`. URL score-source failures are handled by
the API: one usable score produces a low-confidence `Partial` result, while no
usable score produces `Incomplete`. Warnings, failed payment checks, and
unverifiable references require review.

`app/main.py` decodes uploaded image bytes and composes the local checks. For a
supported URL it invokes `app/services/url_vet_check.py`, which uses the
loopback-only client and maps the response into the common check contract. For
other content types it emits `url_vet: not_applicable` without a request. The
Streamlit interface renders decoded content using `st.code`, rather than a
clickable link.

## Testing

E2-US3 coverage includes common-check aggregation, failed-check propagation,
Review required results, non-clickable presentation, mocked url.vet handling,
and API-level tests that assert plain text, payment, malformed URL, unsupported
URI, and structured non-web payloads do not invoke url.vet.

url.vet's own outbound-inspection safeguards are provided by the separately
self-hosted service. QR Shield's boundary remains loopback-only, bounded, and
non-clickable: it does not expose the target to the user's browser. When
url.vet is unavailable, the local model may provide a clearly labelled partial
advisory result, but it is never presented as a replacement for completed
url.vet evidence.

# E3-US1: Multi-Source Evidence Aggregation

**User story:** As a user who needs a trustworthy warning, I want the system to
combine clearly identified QR-image, URL, domain, reputation, and payment
evidence and explain their contribution, so that I can judge how much
confidence to place in the result.

## Acceptance Criteria

### AC1: Versioned evidence traceability

**Given** one or more versioned evidence sources

**When** a decision is produced

**Then** the result identifies which evidence was used, which checks failed,
and the exact model or rules version.

### AC2: Cautious missing-source handling

**Given** a mandatory high-value evidence source is missing

**When** the decision is assembled

**Then** the system returns an uncertainty or Incomplete state instead of
silently reducing the risk level.

### AC3: Reproducible evaluation evidence

**Given** the locked evaluation datasets

**When** the candidate system is evaluated

**Then** scenario-level effectiveness, calibration, latency, and failure
behaviour are reproducibly reported.

## Tasks

- E3-US1-T01 - Lexical feature and Logistic Regression baseline
- E3-US1-T02 - Evidence adapters and common schema
- E3-US1-T03 - Evidence fusion, model version, and explanation
- E3-US1-T04 - Reliability, calibration, and robustness tests

The application combines local QR-image block inspection, url.vet analysis for
supported web URLs, hostname reputation checks from a versioned offline
denylist, and payment verification where applicable. Local checks report their
own status, while url.vet reports its version, verdict, trust score, reasons,
and risk score through the same traceable check contract.

## Implemented Features

- Use a common source-check schema containing check ID, status, reason codes,
  summary, and safe evidence details.
- Aggregate QR-image, url.vet, domain denylist, and payment evidence into a
  cautious overall outcome.
- Return source versions, url.vet version, decision thresholds, principal
  signals, and failed check IDs with each analysis result.
- Use a versioned, SHA-256-hostname-based local denylist without DNS lookup or
  remote reputation queries.
- Return Incomplete if QR-image inspection, the local denylist, payment checks,
  the decision policy, or all URL score sources cannot complete; preserve one
  usable URL score as a clearly labelled Partial result and return Review
  required for conflicting or adverse evidence.
- Separate observed evidence from model inference in the Streamlit UI.
- Provide a locked six-scenario evaluation manifest and a checked-in report for
  effectiveness, calibration bins, latency, and failure behaviour.

## How It Is Implemented

`app/services/checks.py` provides the common result contract and aggregation
policy. `app/services/denylist.py` normalizes and hashes a hostname locally,
then looks it up in `data/processed/local_denylist.json`; no decoded URL is
resolved or fetched.

`app/main.py` composes source checks from QR-image block inspection, local
denylist lookup, url.vet for supported URLs, and payment verification. It
returns `checks`, `source_versions`, `principal_signals`, `assessment_outcome`,
and `failed_check_ids`. An unavailable mandatory source causes `Incomplete`; if
url.vet or the local judgement source is unavailable but the other source has a
usable score, the API keeps that score as a low-confidence `Partial` result. A
denylist match or payment mismatch causes Review required rather than a safe
conclusion.

`data/evaluation/e3_us1/manifest.json` locks the evaluation payloads and
expected outcomes. `scripts/evaluate_e3_us1.py` generates QR images in memory
from those fixed payloads, applies deterministic source-failure doubles, and
writes the report without any network access.

## Testing

Run the complete regression suite and regenerate the E3-US1 report with:

```bash
python -m unittest discover -s tests -p "test_*.py"
python scripts/evaluate_e3_us1.py
```

E3-US1 coverage includes available, unavailable, and conflicting evidence
sources; url.vet version traceability; cautious Incomplete and Review required
outcomes; calibration-bin output; P50/P95 test latency output; and locked
scenario effectiveness/failure reporting. Automated evaluation uses mocked
url.vet responses and does not require Docker or external network access.

# Phase 3: Evidence-Based Suspicion Policy and Final Verification

Phase 3 adds the supervisor-required distinction between a score, a decision,
and confidence in that decision. The policy is versioned in
`data/evaluation/phase3_calibration/decision_policy.json` and is consumed by
the API, UI, evaluation scripts, and regression tests.

## Current Decision Policy

The current policy is `phase3-decision-policy-v1` and remains **provisional**.
It was selected from a locked, labelled calibration snapshot. The sample is
useful evidence for a safety-first starting point, but it is too small and too
biased toward available URL intelligence to support a claim of statistical
certainty.

The score bands are inclusive/exclusive as follows:

| Level | Score range |
|---|---|
| Low suspicion | `0 <= score < 62` |
| Medium suspicion | `62 <= score < 79` |
| High suspicion | `79 <= score < 100` |
| Dangerous | `score = 100` |

The suspicious decision benchmark is `B = 79`. A score at or above `B` casts a
suspicious vote. The agreement margin is `D = 1` point and is used when
deciding whether two available scores are close enough for high confidence.
These values are not arbitrary UI labels: the calibration report records the
candidate search, split metrics, score distributions, source hashes, and the
limitations behind the selection.

## What the Two Scores Mean

- **url.vet risk score** is the primary 0-100 URL maliciousness signal returned
  by the local url.vet service.
- **Local judgement score** is the retained local Logistic Regression model's
  0-100 lexical URL judgement. It runs only on the decoded URL string and does
  not open or fetch the destination.
- **url.vet trust score** is raw evidence from url.vet. It is displayed for
  traceability and is not QR Shield confidence.
- **QR Shield confidence** describes how strongly the two available sources
  support the final conclusion. It is not the probability that a QR code is
  safe.

For a completed URL decision, each score is mapped to the four bands. The
final displayed band is the more cautious of the two source bands. The
conclusion then follows these rules:

| Evidence | Conclusion |
|---|---|
| Both scores below `B`, with no adverse evidence | Not suspicious |
| Exactly one score reaches `B`, or an adverse verdict is present | Partially suspicious |
| Both scores reach `B` | Suspicious |
| Dangerous score or the policy's dangerous verdict floor | Suspicious, Dangerous level |
| A required score is unavailable | Incomplete; no final level |

The url.vet verdict is never hidden by a low numeric score. A `Suspicious`
verdict sets a minimum High suspicion level. The current policy gives `Risky`
and `Malicious` verdicts a Dangerous floor. Score disagreement produces a
Partially suspicious result with Low confidence and names the source that
crossed the benchmark.

Confidence is assigned separately:

- **High:** both sources agree, differ by no more than `D`, and are not close to
  `B`;
- **Medium:** both sources agree, but one is close to `B` or their difference
  exceeds `D`;
- **Low:** only one source is usable, the sources disagree, or an adverse
  verdict conflicts with the numeric votes;
- **Unavailable:** a mandatory URL analysis is incomplete, or the payload is
  outside supported web URL analysis.

## URL and Non-URL Boundary

Only a valid HTTP/HTTPS URL with a legal hostname is sent to the loopback-only
url.vet client. The service may inspect the destination and related evidence;
QR Shield keeps the image in memory, does not retain it during ordinary
analysis, and never opens the decoded destination in the user's browser.

Plain text, payment payloads, malformed HTTP URLs, unsupported URI schemes,
WiFi strings, vCards, and other structured non-web content receive an explicit
`url_vet: not_applicable` check. They are decoded and displayed when supported,
but the API does not invent a URL risk score or confidence value for them. The
user remains responsible for deciding whether the displayed content is
trustworthy. QR Shield does not automatically open, block, redirect, connect
to WiFi, or initiate a payment.

## Evidence and Reproducible Verification

The checked-in evidence files are:

- `reports/phase3_calibration_report.json` - threshold selection, metrics, and
  calibration limitations;
- `reports/e3_us1_evaluation.json` - six locked evidence-fusion scenarios;
- `reports/phase3_real_qr_evaluation.json` - three safe in-memory reproductions
  linked to reviewed suspicious-source records, with no committed image files;
- `reports/phase3_completion_report.json` - final acceptance evidence produced
  by the verification command.

Run the final verification from the project root:

```bash
python scripts/verify_phase3_completion.py --require-url-vet
```

On Windows, activate the project-specific `qrcode` environment first if you
are using it:

```powershell
conda activate qrcode
python scripts/verify_phase3_completion.py --require-url-vet
```

The command reruns the locked E3-US1 and suspicious-QR evaluations, checks the
non-URL and logo-centre boundaries, reruns the tampering and decoder
regressions, performs a loopback url.vet health smoke test, and records the
machine-readable result in `reports/phase3_completion_report.json`. It does
not include live malicious URLs or binary QR fixtures in that report.

The evidence must still be interpreted honestly: the calibration policy is
provisional, the three ready suspicious cases are safe reproductions rather
than recovered incident images, PhishTank evidence overlaps with url.vet, and
the supervisor's Australian fraud QR remains pending until it is supplied and
cleared for use.

# E3-US2: Privacy and Human Review

**User story:** As a privacy-conscious user, I want QR data to be processed
with minimal retention and any learning or model change to require human
review, so that my information is protected and the system cannot learn from
malicious feedback automatically.

## Acceptance Criteria

### AC1: Memory-only analysis

**Given** a user analyses a QR image

**When** the result is returned

**Then** the image and decoded URL are processed in memory and are not retained
by default.

### AC2: Redacted minimal records

**Given** an event is recorded

**When** logging is enabled

**Then** the record follows the minimisation and redaction policy and excludes
unnecessary QR content or personal data.

### AC3: Authorised human review

**Given** a user submits an explicit report or feedback item

**When** it is received

**Then** it is queued for authorised human review and cannot update the model
automatically.

### AC4: Model-release governance

**Given** a model release is proposed

**When** it is deployed or rolled back

**Then** approval, model version, evaluation evidence, and rollback decision
are recorded.

## Tasks

- Audit image, URL, log, and error-data flows and document retention policy
- Implement default in-memory processing and redacted logging
- Add privacy regression tests and a data-flow review checklist
- Design review-queue authorisation and release approval records
- Add model-governance tests that prevent automatic retraining

The application processes QR images and decoded content in memory. Only when a
user explicitly requests human review does it create a local SQLite record; the
record stores hashes and safe metadata rather than the original image, decoded
URL, hostname, or payment content.

## Implemented Features

- Keep uploaded image data and decoded content in memory for ordinary analysis.
- Provide an explicit local review request endpoint and UI action only for
  Incomplete or Review required results, with a required retention-consent
  checkbox.
- Store SHA-256 hashes of the payload and hostname, plus outcome, model
  version, reason codes, review status, consent timestamp, and policy version
  in a local SQLite queue.
- Require reviewer IDs to be allowlisted through `QR_SHIELD_REVIEWERS` before a
  case may be decided or a release record may be created.
- Require a passing JSON evaluation report and rollback target before an
  approved release can be recorded; record model version, evidence hash,
  reviewer, decision, rollback target, and notes for every audit event.
- Never invoke training, deploy a model, or change model artifacts from user
  feedback or review actions.
- Delete pending review cases after 30 days and resolved cases after 90 days.

## How It Is Implemented

`app/services/review_store.py` is the sole persistence path for explicit review
requests. It creates local SQLite tables for redacted review cases and
model-release audit records. The service hashes payload and hostname values
before writing anything to disk, and reviewer authorisation is checked on every
decision and release action.

`POST /api/v1/review-cases` accepts an explicit local request from the UI and
rejects it unless retention consent is present, then returns only a generated
case ID. `scripts/review_cases.py` provides local
authorised commands to list/decide cases, record release or rollback evidence,
and clean expired records. These commands record governance decisions only;
they contain no training, model replacement, or deployment code.

The retained record fields are limited to SHA-256 hashes, assessment outcome,
model version, reason codes, case/reviewer status, consent timestamp, and the
retention-policy version. Images, raw QR payloads, hostnames, payment values,
accounts, and user identities are not retained.

## Testing

E3-US2 coverage verifies that review records exclude raw hostname/payload data,
unauthorised reviewers are rejected, release auditing does not modify model or
metrics files, expired pending records are deleted, ordinary analysis creates
no review database, consent is required, and approval requires passing
evaluation evidence plus a rollback target. The complete test suite remains
runnable with:

```bash
python -m unittest discover -s tests -p "test_*.py"
```

# E4-US1: Decoder Robustness and Generalization

The QR decoder was upgraded to ZXing (`pyzxing`) with an OpenCV fallback. A
reproducible benchmark measures decode accuracy across real content types and
controlled distortions, so later changes cannot silently regress decoding.

## Dataset

Real sample codes live under `data/test_images/e4_us1_robustness/` (URL, WeChat,
Alipay, WiFi, vCard, plain text, and one proprietary WeChat mini-program code
that no open decoder can read). `scripts/generate_robustness_perturbations.py`
derives deterministic rotation, perspective, and Gaussian-noise variants under
`perturbed/`. Ground truth for each source is recorded in
`robustness_manifest.json` and should be verified against a real scan.

## Metric and pass criteria

Each decode is scored Correct, Miss (no output), or Wrong (output does not match
the true payload). The evaluation reports OpenCV-only, ZXing-only, and the real
pipeline (ZXing first, OpenCV fallback). It passes when:

- the pipeline decodes at least as many images as either decoder alone;
- the pipeline correct-rate on decodable images meets the target;
- the pipeline never produces a Wrong decode (a security floor); and
- the proprietary, non-standard code is cleanly rejected.

## Running

```bash
python scripts/generate_robustness_perturbations.py
python scripts/evaluate_robustness.py
```

The machine-readable report is written to `reports/robustness_metrics.json`.
