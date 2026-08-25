"""Student-focused English Streamlit interface for QR Shield."""

from __future__ import annotations

import streamlit as st

from app.ui.api_client import (
    APIClientError,
    analyze_qr,
    check_api_health,
    create_review_case,
    get_api_base_url,
)
from app.ui.presentation import (
    get_api_error_message,
    get_decision_display,
    get_qr_content_display,
    get_result_presentation,
    get_score_evidence_display,
    get_unverifiable_payment_message,
)


st.set_page_config(
    page_title="QR Shield — Check before you trust",
    page_icon="🛡️",
    layout="centered",
)

st.markdown(
    """
    <style>
      .stApp { background: #f6f8fc; }
      .block-container { max-width: 760px; padding-top: 2.5rem; padding-bottom: 4rem; }
      .qr-hero {
        padding: 1.5rem 1.6rem;
        border: 1px solid #dce3ef;
        border-radius: 18px;
        background: linear-gradient(135deg, #ffffff 0%, #eef4ff 100%);
        box-shadow: 0 8px 24px rgba(15, 38, 80, 0.06);
        margin-bottom: 1.25rem;
      }
      .qr-eyebrow {
        color: #2457a7;
        font-size: 0.78rem;
        font-weight: 750;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        margin-bottom: 0.35rem;
      }
      .qr-hero h1 { color: #10233f; font-size: 2.15rem; margin: 0 0 0.45rem; }
      .qr-hero p { color: #42536c; font-size: 1.02rem; line-height: 1.55; margin: 0; }
      .qr-trust {
        color: #294363;
        background: #edf6f1;
        border-left: 4px solid #23865f;
        border-radius: 10px;
        padding: 0.8rem 1rem;
        margin: 0.5rem 0 1.25rem;
      }
      .stButton > button { min-height: 48px; border-radius: 10px; font-weight: 700; }
      [data-testid="stFileUploader"] {
        background: #ffffff;
        border: 1px solid #dce3ef;
        border-radius: 14px;
        padding: 0.8rem;
      }
      [data-testid="stMetric"] {
        background: #ffffff;
        border: 1px solid #dce3ef;
        border-radius: 8px;
        padding: 0.8rem 1rem;
        min-height: 108px;
      }
      [data-testid="stMetricValue"] { font-size: 1.35rem; line-height: 1.25; overflow-wrap: anywhere; }
      [data-testid="stExpander"] {
        background: #ffffff;
        border-color: #dce3ef;
        border-radius: 12px;
      }
      code { overflow-wrap: anywhere; white-space: pre-wrap !important; }
      @media (max-width: 640px) {
        .block-container { padding-top: 4rem; }
        .qr-hero { padding: 1.15rem; }
        .qr-hero h1 { font-size: 1.75rem; }
      }
    </style>
    """,
    unsafe_allow_html=True,
)


def _render_alert(tone: str, title: str, summary: str) -> None:
    message = f"**{title}**\n\n{summary}"
    if tone == "success":
        st.success(message, icon="✅")
    elif tone == "error":
        st.error(message, icon="🛑")
    elif tone == "warning":
        st.warning(message, icon="⚠️")
    else:
        st.info(message, icon="ℹ️")


def _render_payment(payment: dict) -> None:
    if payment.get("status") == "not_applicable":
        return
    st.subheader("Payment verification")
    status_text = str(payment.get("status", "incomplete")).replace("_", " ").title()
    summary = str(payment.get("summary", "Payment details could not be verified."))
    if payment.get("status") == "passed":
        st.success(f"**{status_text}** — {summary}")
    elif payment.get("status") == "unverifiable":
        st.warning(get_unverifiable_payment_message())
    else:
        st.error(f"**{status_text}** — {summary}")

    evidence = payment.get("evidence") or {}
    if evidence:
        columns = st.columns(3)
        columns[0].metric("Merchant", str(evidence.get("merchant_id", "Unknown")))
        columns[1].metric("Payee", str(evidence.get("payee_masked", "Unknown")))
        amount = str(evidence.get("amount", "Unknown"))
        currency = str(evidence.get("currency", ""))
        columns[2].metric("Amount", f"{currency} {amount}".strip())


def _render_technical_details(result: dict) -> None:
    with st.expander("Technical evidence and decoded content"):
        st.markdown("**Decoded content**")
        st.code(str(result.get("decoded_text", "")), language=None)

        block = result.get("block_inspection") or {}
        st.markdown("**QR image inspection**")
        st.write(
            f"{str(block.get('status', 'incomplete')).title()}: "
            f"{block.get('summary', 'No inspection summary was returned.')}"
        )
        regions = (block.get("evidence") or {}).get("regions") or []
        if regions:
            st.caption(
                "Regions: "
                + ", ".join(
                    f"{str(item.get('region', '')).replace('_', ' ').title()} "
                    f"({item.get('status', 'unknown')})"
                    for item in regions
                )
            )

        checks = result.get("checks") or []
        if checks:
            st.markdown("**Observed evidence sources**")
            for item in checks:
                check_name = str(item.get("check_id", "check")).replace("_", " ").title()
                check_status = str(item.get("status", "unknown")).replace("_", " ").title()
                st.write(f"- **{check_name}** [{check_status}]: {item.get('summary', '')}")

        source_versions = result.get("source_versions") or {}
        if source_versions:
            st.markdown("**Source versions**")
            for source, version in source_versions.items():
                st.write(f"- {source.replace('_', ' ').title()}: `{version}`")

        signals = result.get("principal_signals") or []
        if signals:
            st.markdown("**Reason codes**")
            st.code(", ".join(signals), language=None)


def _render_review_request(result: dict) -> None:
    if result.get("assessment_outcome") not in {"Review required", "Incomplete"}:
        return
    with st.expander("Request human review"):
        st.write(
            "Only redacted evidence will be retained. The original image, decoded URL "
            "and payment payload will not be stored."
        )
        consent = st.checkbox(
            "I consent to retain redacted evidence for authorised human review.",
            key="review_consent",
        )
        if st.button("Submit review request", disabled=not consent, use_container_width=True):
            try:
                case_id = create_review_case(get_api_base_url(), result, consent)
            except APIClientError:
                st.error("The review request could not be created. Please try again.")
            else:
                st.success(f"Review request created. Case ID: {case_id}")


def _render_decision_summary(decision: dict[str, object]) -> None:
    st.subheader("Decision summary")
    columns = st.columns(3)
    columns[0].metric("Final suspicion level", str(decision["final_level"]))
    columns[1].metric("Conclusion", str(decision["conclusion"]))
    columns[2].metric("QR Shield confidence", str(decision["confidence_level"]))
    if decision["confidence_level"] == "Not applicable":
        st.caption(
            "Confidence is not applicable because this QR content is outside supported web URL risk analysis."
        )
    else:
        st.caption(
            "Confidence describes how strongly the available evidence supports this conclusion. "
            "It is not a probability that the QR code is safe."
        )


def _render_score_evidence(evidence: dict[str, object]) -> None:
    if not evidence["has_any_evidence"]:
        return
    st.subheader("Score evidence")
    columns = st.columns(3)
    columns[0].metric(str(evidence["risk_label"]), str(evidence["risk_score"]))
    columns[0].caption(str(evidence["risk_context"]))
    columns[1].metric("Local judgement score", str(evidence["judgement_score"]))
    columns[1].caption(str(evidence["judgement_context"]))
    columns[2].metric("url.vet trust evidence", str(evidence["trust_score"]))
    columns[2].caption("Raw url.vet evidence; this is not QR Shield confidence.")
    st.write(f"url.vet verdict: **{evidence['verdict']}**")
    if evidence["url_vet_status"] in {"incomplete", "warning"}:
        if evidence["url_vet_status"] == "incomplete" and evidence["risk_score"] == "Not available":
            st.info(
                "url.vet did not return a risk score. The local judgement score is "
                "shown as a partial advisory result; do not treat it as a complete "
                "two-source decision."
            )
        else:
            st.info(
                "url.vet returned partial evidence. The available score is shown, "
                "but the URL inspection did not complete; do not treat it as a "
                "complete safety conclusion."
            )


def _render_decision_basis(decision: dict[str, object]) -> None:
    if not decision["available"]:
        return
    st.subheader("Decision basis")
    confidence_reason = str(decision["confidence_reason"])
    if decision["has_score_conflict"] or decision["has_verdict_conflict"]:
        st.warning(confidence_reason)
    else:
        st.write(f"**Confidence basis:** {confidence_reason}")

    reasons = list(decision["decision_reasons"])
    if reasons:
        st.markdown("**How the sources were combined**")
        for reason in reasons:
            st.write(f"- {reason}")

    threshold_ranges = list(decision["threshold_ranges"])
    if threshold_ranges:
        st.markdown("**Policy thresholds**")
        st.write(
            f"Suspicious benchmark: **{decision['benchmark']}**. "
            f"Agreement margin: **{decision['agreement_margin']} point(s)**."
        )
        for level, score_range in threshold_ranges:
            st.write(f"- **{level}:** {score_range}")
        st.caption(f"Decision policy: {decision['policy']}")


def _render_source_reasons(evidence: dict[str, object]) -> None:
    url_vet_reasons = list(evidence["url_vet_reasons"])
    judgement_reasons = list(evidence["judgement_reasons"])
    if not url_vet_reasons and not judgement_reasons:
        return
    st.subheader("Evidence from each source")
    columns = st.columns(2)
    columns[0].markdown("**url.vet inspection**")
    if url_vet_reasons:
        for reason in url_vet_reasons:
            columns[0].write(f"- {reason}")
    else:
        columns[0].caption("No url.vet explanation was returned.")
    columns[1].markdown("**Local lexical judgement**")
    if judgement_reasons:
        for reason in judgement_reasons:
            columns[1].write(f"- {reason}")
    else:
        columns[1].caption("No local lexical explanation was returned.")


def render_result(result: dict) -> None:
    presentation = get_result_presentation(result)
    content_display = get_qr_content_display(result)
    decision = get_decision_display(result)
    score_evidence = get_score_evidence_display(result)
    st.divider()
    st.subheader("Overall result")
    _render_alert(
        presentation["tone"],
        presentation["title"],
        presentation["summary"],
    )

    hostname = str(result.get("hostname") or "")
    if hostname:
        st.write(f"Destination hostname: **`{hostname}`**")
        st.caption("The hostname is isolated here to make look-alike domains easier to spot.")

    _render_decision_summary(decision)
    _render_score_evidence(score_evidence)
    _render_decision_basis(decision)
    _render_source_reasons(score_evidence)

    st.subheader("QR content type")
    st.write(str(content_display["summary"]))
    guidance = content_display.get("guidance")
    if guidance:
        st.info(str(guidance))
    content_columns = st.columns(2)
    content_columns[0].metric("Type", str(content_display["label"]))
    content_columns[1].metric("Decoded as", str(result.get("content_type") or "unknown").replace("_", " ").title())
    content_fields = list(content_display.get("fields") or [])
    if content_fields:
        for label, value in content_fields:
            st.write(f"- **{label}**: {value}")

    _render_payment(result.get("payment") or {})

    st.subheader("Recommended action")
    st.info(presentation["action"], icon="👉")

    _render_technical_details(result)
    _render_review_request(result)
    st.caption(
        "QR Shield provides analysis and feedback only. You make the final decision. "
        "It does not automatically open, block, redirect, connect, or pay."
    )


st.markdown(
    """
    <section class="qr-hero">
      <div class="qr-eyebrow">Student safety tool</div>
      <h1>Check a QR code before you trust it</h1>
      <p>Inspect a QR image for suspicious destinations, visible tampering and payment changes before taking action.</p>
    </section>
    <div class="qr-trust">🛡️ Your image is processed locally and is not retained. Valid web URLs are sent to the local url.vet service to inspect the destination, which is never opened automatically.</div>
    """,
    unsafe_allow_html=True,
)

uploaded_file = st.file_uploader(
    "Upload a QR image",
    type=["png", "jpg", "jpeg"],
    help="Supported formats: PNG, JPG and JPEG. Maximum file size: 5 MiB.",
)

current_upload_key = None
if uploaded_file is not None:
    upload_bytes = uploaded_file.getvalue()
    current_upload_key = f"{uploaded_file.name}:{len(upload_bytes)}"
    if st.session_state.get("upload_key") != current_upload_key:
        st.session_state["upload_key"] = current_upload_key
        st.session_state.pop("last_result", None)
        st.session_state.pop("review_consent", None)
    st.image(upload_bytes, caption="Selected QR image", width=260)
else:
    upload_bytes = b""

analyse_clicked = st.button(
    "Analyse QR Code",
    type="primary",
    disabled=uploaded_file is None,
    use_container_width=True,
)

if analyse_clicked and uploaded_file is not None:
    if not check_api_health(get_api_base_url()):
        st.error(get_api_error_message(0))
    else:
        with st.spinner("Analysing the QR code securely..."):
            try:
                st.session_state["last_result"] = analyze_qr(
                    get_api_base_url(),
                    uploaded_file.name,
                    upload_bytes,
                    uploaded_file.type or "application/octet-stream",
                )
            except APIClientError as exc:
                st.error(get_api_error_message(exc.status_code or 0))

if "last_result" in st.session_state:
    render_result(st.session_state["last_result"])
