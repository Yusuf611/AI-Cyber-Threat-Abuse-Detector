import os
import time
import hashlib
from datetime import datetime
import json

import streamlit as st
import joblib
import pandas as pd
import plotly.express as px
import requests
from dotenv import load_dotenv
from scripts.url_features import extract_url_features
from scripts.xai_url import explain_url
from scripts.xai_text import top_text_tokens
from scripts.ip_reputation import check_ip_reputation

st.set_page_config(
    page_title="AI Cyber Threat & Abuse Detector",
    page_icon="🛡️",
    layout="wide",
)

load_dotenv()
VT_API_KEY = os.getenv("VT_API_KEY")
VT_BASE = "https://www.virustotal.com/api/v3"
VT_HEADERS = {"x-apikey": VT_API_KEY} if VT_API_KEY else {}

st.markdown(
    """
    <style>
    .stApp {
        background: linear-gradient(180deg, #f6f8ff 0%, #ffffff 40%);
        color: #0f1723;
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue",
                     Arial, "Noto Sans", "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
    }

    .app-title { font-size:28px; font-weight:700; margin-bottom:4px; color:#0b2545; }
    .muted { color:#6b7280; margin-bottom:12px; }

    .card { padding:18px; border-radius:12px; background:linear-gradient(180deg,#ffffff,#fbfdff); box-shadow: 0 8px 30px rgba(12,38,63,0.06); border:1px solid rgba(11,37,69,0.04); }
    .result-box { padding:14px; border-radius:10px; background:#ffffff; border-left:6px solid rgba(59,130,246,0.18); box-shadow: 0 6px 18px rgba(11,37,69,0.03); margin-top:8px; }
    .small { font-size:16px; color:#fff; }

    [data-testid="stSidebar"] {
        background: linear-gradient(180deg,#0b2545ee,#08203be6);
        color: #fff;
        padding-top: 20px;
        border-top-right-radius: 16px;
        border-bottom-right-radius: 16px;
    }
    [data-testid="stSidebar"] .css-1d391kg, [data-testid="stSidebar"] .css-1avcm0n {
        color: #ffffff;
    }

    .stButton>button, .stDownloadButton>button {
        background: #fff;
        color: #0b2545;
        border: 2px solid transparent;
        padding: 8px 14px;
        border-radius: 10px;
        box-shadow: 0 6px 18px rgba(37,99,235,0.08);
        font-weight:700;
        position: relative;
        transition: all 150ms ease-in-out;
    }
    .stButton>button:hover { transform: translateY(-2px); box-shadow: 0 10px 26px rgba(37,99,235,0.12); }
    .stButton>button:before {
        content: "🔎";
        display:inline-block; margin-right:8px; vertical-align:middle;
    }

    .stButton>button[aria-label] {
        border-image: linear-gradient(90deg,#7c3aed,#2563eb) 1;
    }

    .stTextInput>div>div>input, .stTextArea>div>div>textarea {
        border-radius: 10px; 
        padding: 10px;
        border: 1px solid rgba(11,37,69,0.12);
        background: #ffffff;
        color: #0b1220;
        box-shadow: inset 0 1px 0 rgba(11,37,69,0.02);
    }
    .stTextInput>div>div>input::placeholder, .stTextArea>div>div>textarea::placeholder { color:#94a3b8; }

    .css-1a3b8rf, .css-uf99v8 { background:#0f1723; color:#fff; border-radius:12px; }
    .css-1a3b8rf .stFileUploaderDropzone, .css-uf99v8 .stFileUploaderDropzone { background:#0f1723; color:#fff; }

    .stMarkdown, .stWrite { color:#0b1220; }

    .stExpander > div:nth-child(1) {
        border-radius: 10px; border: 1px solid rgba(11,37,69,0.04); padding: 0.6rem; background: #ffffff;
    }

    .stJson, pre, code {
        background: #0b1220;
        color: #e6eef8;
        padding: 12px;
        border-radius: 8px;
        overflow:auto;
    }

    .stAlert, .stSuccess, .stWarning, .stError, .stInfo {
        border-radius: 10px; padding: 10px 14px; box-shadow: none;
    }

    .stColumns>div { padding: 6px 10px; }

    footer, .reportview-container footer { color:#94a3b8; }

    /* File uploader styling */
    [data-testid="stFileUploader"] section {
        border-radius: 10px;
        border: 1px dashed rgba(11,37,69,0.25);
        background: #f9fbff;
    }
    [data-testid="stFileUploader"] button {
        background: #2563eb !important;
        color: #ffffff !important;
        border-radius: 8px;
        padding: 6px 14px;
        font-weight: 600;
    }
    /* Make all uploader texts visible (drag & drop, help text, etc.) */
    [data-testid="stFileUploader"],
    [data-testid="stFileUploader"] * {
        color: #0b1220 !important;
    }

    @media (max-width: 800px) {
        .app-title { font-size:22px; }
        .card { padding:12px; }
    }
    </style>
    """,
    unsafe_allow_html=True,
)

def sha256_of_bytes(b: bytes) -> str:
    h = hashlib.sha256()
    h.update(b)
    return h.hexdigest()

def vt_scan_url(url: str):
    endpoint = f"{VT_BASE}/urls"
    resp = requests.post(endpoint, headers=VT_HEADERS, data={"url": url})
    resp.raise_for_status()
    return resp.json()

def vt_get_url_analysis(analysis_id: str):
    endpoint = f"{VT_BASE}/analyses/{analysis_id}"
    resp = requests.get(endpoint, headers=VT_HEADERS)
    resp.raise_for_status()
    return resp.json()

def vt_get_file_report_by_hash(sha256_hash: str):
    endpoint = f"{VT_BASE}/files/{sha256_hash}"
    resp = requests.get(endpoint, headers=VT_HEADERS)
    if resp.status_code == 200:
        return resp.json()
    elif resp.status_code == 404:
        return None
    else:
        resp.raise_for_status()

def vt_upload_file(file_bytes: bytes, filename="upload.bin"):
    endpoint = f"{VT_BASE}/files"
    files = {"file": (filename, file_bytes)}
    resp = requests.post(endpoint, headers=VT_HEADERS, files=files)
    resp.raise_for_status()
    return resp.json()

def vt_get_analysis_by_id(analysis_id: str):
    endpoint = f"{VT_BASE}/analyses/{analysis_id}"
    resp = requests.get(endpoint, headers=VT_HEADERS)
    resp.raise_for_status()
    return resp.json()

base_path = os.path.dirname(os.path.abspath(__file__))
models_path = os.path.join(base_path, "models")
DB_PATH = os.path.join(base_path, "malware_db.json")

def load_malware_db():
    if not os.path.exists(DB_PATH):
        return {}
    try:
        with open(DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def scan_hash_local(file_hash: str):
    malware_db = load_malware_db()
    if file_hash in malware_db:
        return {
            "is_malware": True,
            "label": malware_db[file_hash],
            "sha256": file_hash,
            "status": "Malicious (Local DB)"
        }
    else:
        return {
            "is_malware": False,
            "label": "Unknown file (not in local DB)",
            "sha256": file_hash,
            "status": "Unknown (Local DB)"
        }

url_model = None
text_model = None
tfidf = None

try:
    url_model = joblib.load(os.path.join(models_path, "url_model.joblib"))
    text_model = joblib.load(os.path.join(models_path, "text_model.joblib"))
    tfidf = joblib.load(os.path.join(models_path, "tfidf_vectorizer.joblib"))
except Exception as e:
    st.warning(f"Warning loading models: {e}. Local ML features will be disabled until models are available.")

st.markdown("<div class='app-title'>AI Cyber Threat & Abuse Detector</div>", unsafe_allow_html=True)
st.sidebar.title("Threat Prediction")
st.sidebar.markdown("Quick tools — choose a page")
page = st.sidebar.radio("Navigate", ("URL Scanner", "Text Analyzer", "File Scanner", "IP Reputation"))

st.sidebar.markdown("---")
st.sidebar.markdown("Final Year Project")
st.sidebar.markdown("Yusuf Ejaz, Prakash Kumar, Anmol Kumar, Narayan Mahato")

# Logging disabled (option 1)
def save_scan_log(scan_type, input_data, result, confidence=0.0, raw=None):
    return False, ""


# URL Scanner Page

if page == "URL Scanner":
    st.markdown("<div class='app-title'>🔗 URL Scanner</div>", unsafe_allow_html=True)
    st.markdown("<div class='muted'>Scan URLs locally with your ML model or submit to VirusTotal for external analysis.</div>", unsafe_allow_html=True)

    left, right = st.columns([1, 1.2])
    with left:
        url = st.text_input("Enter URL", placeholder="https://example.com")
        st.write("")
        scan_local = st.button("Scan (Local Model)")
        scan_vt = st.button("Submit to VirusTotal")
    with right:
        st.markdown("# Result")

        if scan_local:
            if url_model is None:
                st.error("Local URL model not available. Place model file in models/ and restart the app.")
            elif not url or not url.strip():
                st.warning("Enter a URL first.")
            else:
                feats = extract_url_features(url)
                df_feat = pd.DataFrame([feats])
                prob = url_model.predict_proba(df_feat)[0][1]
                label = "⚠️ Malicious" if prob > 0.5 else "✅ Safe"
                color = "red" if prob > 0.5 else "green"
                st.markdown(
                    f"<div class='result-box'><h3 style='color:{color}; margin:0;'>{label} — Confidence: {prob:.2f}</h3></div>",
                    unsafe_allow_html=True,
                )

                ok, msg = save_scan_log("URL", url, label, confidence=prob)
                if msg:
                    if ok:
                        st.success(msg)
                    else:
                        st.warning(msg)

                with st.expander("Why the model predicted this?"):
                    try:
                        explanation = explain_url(url)
                        for feature, val in explanation:
                            st.write(f"- **{feature}** → {val:.4f}")
                    except Exception:
                        st.write("Explanation service unavailable.")

        if scan_vt:
            if not VT_API_KEY:
                st.error("VT_API_KEY not set. Add it to `.env` to use VirusTotal.")
            elif not url or not url.strip():
                st.warning("Enter a URL first.")
            else:
                with st.spinner("Submitting URL to VirusTotal..."):
                    try:
                        resp = vt_scan_url(url)
                        analysis_id = resp.get("data", {}).get("id")
                        report = None
                        for _ in range(12):
                            time.sleep(2)
                            report = vt_get_url_analysis(analysis_id)
                            status = report.get("data", {}).get("attributes", {}).get("status")
                            if status == "completed":
                                break
                        if report:
                            st.success("Analysis completed.")
                            stats = report.get("data", {}).get("attributes", {}).get("stats", {})
                            malicious = stats.get("malicious", 0) if stats else 0
                            total_votes = sum(stats.values()) if stats else 0
                            label = "⚠️ Malicious " if malicious > 0 else "✅ Clean "
                            color = "red" if malicious > 0 else "green"
                            st.markdown(
                                f"<div class='result-box'><h3 style='color:{color}; margin:0;'>{label}</h3><p>Detections: {malicious}/{total_votes} engines</p></div>",
                                unsafe_allow_html=True,
                            )

                            if stats:
                                filtered_stats = {k: v for k, v in stats.items() if v > 0}
                                if filtered_stats:
                                    vt_df = pd.DataFrame(
                                        {"label": list(filtered_stats.keys()), "count": list(filtered_stats.values())}
                                    )
                                    fig = px.pie(vt_df, names="label", values="count", title="Engine verdict breakdown")
                                    st.plotly_chart(fig, use_container_width=True)

                            with st.expander("Raw VirusTotal JSON"):
                                st.json(report)

                            ok, msg = save_scan_log("URL (VT)", url, label, confidence=malicious, raw=report)
                            if msg:
                                if ok:
                                    st.success(msg)
                                else:
                                    st.warning(msg)
                        else:
                            st.warning("No completed analysis yet. Try again in a moment.")
                    except Exception as e:
                        st.error(f"Error: {e}")


# Text Analyzer Page

elif page == "Text Analyzer":
    st.markdown("<div class='app-title'>💬 Text Analyzer</div>", unsafe_allow_html=True)
    st.markdown("<div class='muted'>Detect toxic or cyberbullying content using the local text model.</div>", unsafe_allow_html=True)

    text = st.text_area("Enter text to analyze", height=180, placeholder="Paste a message to analyze...")
    if st.button("Analyze Text"):
        if not text or not text.strip():
            st.warning("Please enter text.")
        elif text_model is None or tfidf is None:
            st.error("Local text model or TF-IDF vectorizer not available. Place model files in models/ and restart the app.")
        else:
            X = tfidf.transform([text])
            pred = text_model.predict(X)[0]
            if pred != "Safe":
                st.error(f"🚨 Detected: **{pred}**")
            else:
                st.success("✅ No issues detected")
            ok, msg = save_scan_log("Text", text[:400], pred, confidence=0.0)
            if msg:
                if ok:
                    st.success(msg)
                else:
                    st.warning(msg)

            with st.expander("Top contributing tokens"):
                try:
                    tokens = top_text_tokens(tfidf, text_model, text)
                    for tok, score in tokens:
                        st.write(f"- **{tok}** → {score:.4f}")
                except Exception:
                    st.write("Token explanation unavailable.")


# File Scanner Page

elif page == "File Scanner":
    st.markdown("<div class='app-title'>📁 File Scanner</div>", unsafe_allow_html=True)
    st.markdown(
        "<div class='muted'>First check against your local malware signature DB, then optionally query VirusTotal for detailed multi-engine analysis.</div>",
        unsafe_allow_html=True,
    )

    uploaded = st.file_uploader("Drag & drop a file or click to browse", type=None)
    manual_hash = st.text_input("Or paste a SHA256 hash to lookup", placeholder="paste full sha256 here")
    lookup_clicked = st.button("Lookup Hash")

    if uploaded:
        st.write(f"Uploaded: **{uploaded.name}** — {uploaded.size} bytes")
        if st.button("Find Result"):
            file_bytes = uploaded.read()
            file_hash = sha256_of_bytes(file_bytes)
            st.write("SHA256:", file_hash)

            st.markdown("### 🔒 Local Signature Scan")
            local_result = scan_hash_local(file_hash)
            if local_result["is_malware"]:
                st.markdown(
                    f"<div class='result-box'><h3 style='color:red; margin:0;'>🚨 Malicious (Local DB)</h3><p>{local_result['label']}</p><p><small>{local_result['sha256']}</small></p></div>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"<div class='result-box'><h3 style='color:green; margin:0;'>✅ Not found in local DB</h3><p>{local_result['label']}</p><p><small>{local_result['sha256']}</small></p></div>",
                    unsafe_allow_html=True,
                )

            ok, msg = save_scan_log("File (Local DB)", file_hash, local_result["status"], confidence=1.0)
            if msg:
                if ok:
                    st.success(msg)
                else:
                    st.warning(msg)

            st.markdown("---")
            st.markdown("### 🌐 File Scan")

            if not VT_API_KEY:
                st.error("VT_API_KEY missing; add it to .env to use VT features.")
            else:
                try:
                    rep = vt_get_file_report_by_hash(file_hash)
                    if rep:
                        st.success("Found existing report.")
                        stats = rep.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0) if stats else 0
                        total_vendors = sum(stats.values()) if stats else 0
                        label = "⚠️ Malicious " if malicious > 0 else "✅ Clean"
                        color = "red" if malicious > 0 else "green"
                        st.markdown(
                            f"<div class='result-box'><h3 style='color:{color}; margin:0;'>{label}</h3><p>Detections: {malicious}/{total_vendors} engines</p></div>",
                            unsafe_allow_html=True,
                        )

                        if stats:
                            filtered_stats = {k: v for k, v in stats.items() if v > 0}
                            if filtered_stats:
                                vt_df = pd.DataFrame(
                                    {"label": list(filtered_stats.keys()), "count": list(filtered_stats.values())}
                                )
                                fig = px.pie(vt_df, names="label", values="count", title="Engine verdict breakdown")
                                st.plotly_chart(fig, use_container_width=True)

                        with st.expander("Raw VirusTotal JSON"):
                            st.json(rep)

                        ok, msg = save_scan_log("File", file_hash, label, confidence=malicious, raw=rep)
                        if msg:
                            if ok:
                                st.success(msg)
                            else:
                                st.warning(msg)
                    else:
                        st.warning("No existing report. Uploading file to VirusTotal for analysis...")
                        try:
                            upload_resp = vt_upload_file(file_bytes, filename=uploaded.name)
                            with st.expander("Upload response (VT)"):
                                st.json(upload_resp)
                            analysis_id = upload_resp.get("data", {}).get("id")
                            final_analysis = None
                            for _ in range(12):
                                time.sleep(3)
                                try:
                                    analysis = vt_get_analysis_by_id(analysis_id)
                                    status = analysis.get("data", {}).get("attributes", {}).get("status")
                                    if status == "completed":
                                        final_analysis = analysis
                                        break
                                except Exception:
                                    pass
                            if final_analysis:
                                st.success("VirusTotal analysis completed.")
                                stats = final_analysis.get("data", {}).get("attributes", {}).get("stats", {})
                                malicious = stats.get("malicious", 0) if stats else 0
                                total_vendors = sum(stats.values()) if stats else 0
                                label = "⚠️ Malicious" if malicious > 0 else "✅ Clean"
                                color = "red" if malicious > 0 else "green"
                                st.markdown(
                                    f"<div class='result-box'><h3 style='color:{color}; margin:0;'>{label}</h3><p>Detections: {malicious}/{total_vendors} engines</p></div>",
                                    unsafe_allow_html=True,
                                )

                                if stats:
                                    filtered_stats = {k: v for k, v in stats.items() if v > 0}
                                    if filtered_stats:
                                        vt_df = pd.DataFrame(
                                            {"label": list(filtered_stats.keys()), "count": list(filtered_stats.values())}
                                        )
                                        fig = px.pie(
                                            vt_df,
                                            names="label",
                                            values="count",
                                            title="Engine verdict breakdown",
                                        )
                                        st.plotly_chart(fig, use_container_width=True)

                                with st.expander("Raw VirusTotal JSON"):
                                    st.json(final_analysis)

                                ok, msg = save_scan_log("File", file_hash, label, confidence=malicious, raw=final_analysis)
                                if msg:
                                    if ok:
                                        st.success(msg)
                                    else:
                                        st.warning(msg)
                            else:
                                st.warning("Analysis not complete. Try again later.")
                        except Exception as e:
                            st.error(f"Upload error: {e}")
                except Exception as e:
                    st.error(f"Error: {e}")

    # Hash lookup via button
    if lookup_clicked:
        hash_val = manual_hash.strip()
        if not hash_val:
            st.warning("Paste a SHA256 hash.")
        else:
            st.markdown("### 🔒 Local Signature Scan")
            local_result = scan_hash_local(hash_val)
            if local_result["is_malware"]:
                st.markdown(
                    f"<div class='result-box'><h3 style='color:red; margin:0;'>🚨 Malicious (Local DB)</h3><p>{local_result['label']}</p><p><small>{local_result['sha256']}</small></p></div>",
                    unsafe_allow_html=True,
                )
            else:
                st.markdown(
                    f"<div class='result-box'><h3 style='color:green; margin:0;'>✅ Not found in local DB</h3><p>{local_result['label']}</p><p><small>{local_result['sha256']}</small></p></div>",
                    unsafe_allow_html=True,
                )

            ok, msg = save_scan_log("File (Local DB)", hash_val, local_result["status"], confidence=1.0)
            if msg:
                if ok:
                    st.success(msg)
                else:
                    st.warning(msg)

            st.markdown("---")
            st.markdown("### 🌐 Hash Scan")

            if not VT_API_KEY:
                st.error("VT_API_KEY missing.")
            else:
                try:
                    rep = vt_get_file_report_by_hash(hash_val)
                    if rep:
                        st.success("Found report.")
                        stats = rep.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0) if stats else 0
                        total_vendors = sum(stats.values()) if stats else 0
                        label = "⚠️ Malicious" if malicious > 0 else "✅ Clean"
                        color = "red" if malicious > 0 else "green"
                        st.markdown(
                            f"<div class='result-box'><h3 style='color:{color}; margin:0;'>{label}</h3><p>Detections: {malicious}/{total_vendors} engines</p></div>",
                            unsafe_allow_html=True,
                        )

                        if stats:
                            filtered_stats = {k: v for k, v in stats.items() if v > 0}
                            if filtered_stats:
                                vt_df = pd.DataFrame(
                                    {"label": list(filtered_stats.keys()), "count": list(filtered_stats.values())}
                                )
                                fig = px.pie(vt_df, names="label", values="count", title="Engine verdict breakdown")
                                st.plotly_chart(fig, use_container_width=True)

                        with st.expander("Raw VirusTotal JSON"):
                            st.json(rep)

                        ok, msg = save_scan_log("File", hash_val, label, confidence=malicious, raw=rep)
                        if msg:
                            if ok:
                                st.success(msg)
                            else:
                                st.warning(msg)
                    else:
                        st.warning("No report exists for that hash.")
                except Exception as e:
                    st.error(f" Error: {e}")


# IP Reputation Page

elif page == "IP Reputation":
    st.markdown("<div class='app-title'>🌐 IP Reputation Checker</div>", unsafe_allow_html=True)
    st.markdown("<div class='muted'>Check IP reputation using AbuseIPDB (via your scripts.ip_reputation module).</div>", unsafe_allow_html=True)

    ip = st.text_input("Enter IP", placeholder="8.8.8.8")
    if st.button("Check IP Reputation"):
        if not ip or not ip.strip():
            st.warning("Enter an IP address.")
        else:
            with st.spinner("Querying IP reputation..."):
                data, error = check_ip_reputation(ip)
            if error:
                st.error(f"Error: {error}")
            else:
                score = data.get("abuseConfidenceScore", 0)
                total_reports = data.get("totalReports", 0)
                country = data.get("countryCode", "Unknown")
                last_report = data.get("lastReportedAt", "N/A")

                if score >= 70:
                    st.error(f"🟥 HIGH RISK — Abuse Score: {score}")
                    result = "High-Risk IP"
                elif score >= 30:
                    st.warning(f"🟧 Suspicious IP — Abuse Score: {score}")
                    result = "Suspicious IP"
                else:
                    st.success(f"🟩 Clean IP — Abuse Score: {score}")
                    result = "Clean IP"

                st.write("### Details")
                st.write(f"- **Country:** {country}")
                st.write(f"- **Total Reports:** {total_reports}")
                st.write(f"- **Last Reported:** {last_report}")

                ok, msg = save_scan_log("IP Reputation", ip, result, confidence=score, raw=data)
                if msg:
                    if ok:
                        st.success(msg)
                    else:
                        st.warning(msg)
