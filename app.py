import os
import time
import hashlib
from datetime import datetime

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
    /* Page background & container */
    .stApp {
        background: linear-gradient(180deg, #f6f8ff 0%, #ffffff 40%);
        color: #0f1723;
        font-family: Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue",
                     Arial, "Noto Sans", "Apple Color Emoji", "Segoe UI Emoji", "Segoe UI Symbol";
    }

    /* App title and subtitle */
    .app-title { font-size:28px; font-weight:700; margin-bottom:4px; color:#0b2545; }
    .muted { color:#6b7280; margin-bottom:12px; }

    /* Card utility */
    .card { padding:18px; border-radius:12px; background:linear-gradient(180deg,#ffffff,#fbfdff); box-shadow: 0 8px 30px rgba(12,38,63,0.06); border:1px solid rgba(11,37,69,0.04); }
    .result-box { padding:14px; border-radius:10px; background:#ffffff; border-left:6px solid rgba(59,130,246,0.18); box-shadow: 0 6px 18px rgba(11,37,69,0.03); }
    .small { font-size:16px; color:#fff; }

    /* Sidebar polish */
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

    /* Buttons and inputs - high contrast and visible on white */
    .stButton>button, .stDownloadButton>button {
        background: #fff; /* white base */
        color: #0b2545; /* dark text for contrast */
        border: 2px solid transparent;
        padding: 8px 14px;
        border-radius: 10px;
        box-shadow: 0 6px 18px rgba(37,99,235,0.08);
        font-weight:700;
        position: relative;
        transition: all 150ms ease-in-out;
    }
    .stButton>button:hover { transform: translateY(-2px); box-shadow: 0 10px 26px rgba(37,99,235,0.12); }
    /* gradient outline to make button pop on white background */
    .stButton>button:before {
        content: "🔎"; /* subtle magnifier on all buttons - looks good for scanners */
        display:inline-block; margin-right:8px; vertical-align:middle;
    }

    /* primary style for important actions */
    .stButton>button[aria-label] {
        border-image: linear-gradient(90deg,#7c3aed,#2563eb) 1; /* gradient border effect in supporting browsers */
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

    /* File uploader clearer on white */
    .css-1a3b8rf, .css-uf99v8 { background:#0f1723; color:#fff; border-radius:12px; }
    .css-1a3b8rf .stFileUploaderDropzone, .css-uf99v8 .stFileUploaderDropzone { background:#0f1723; color:#fff; }

    /* Make uploaded filename and buttons more visible */
    .stMarkdown, .stWrite { color:#0b1220; }

    /* Expander style */
    .stExpander > div:nth-child(1) {
        border-radius: 10px; border: 1px solid rgba(11,37,69,0.04); padding: 0.6rem; background: #ffffff;
    }

    /* JSON and code viewers - lighter and readable on white page */
    .stJson, pre, code {
        background: #0b1220; /* keep dark for code readability */
        color: #e6eef8;
        padding: 12px;
        border-radius: 8px;
        overflow:auto;
    }
    /* But make small summary boxes light */
    .stAlert, .stSuccess, .stWarning, .stError, .stInfo {
        border-radius: 10px; padding: 10px 14px; box-shadow: none;
    }

    /* Make columns align nicely */
    .stColumns>div { padding: 6px 10px; }

    /* Footer small text */
    footer, .reportview-container footer { color:#94a3b8; }

    /* Responsive tweaks */
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


# Load ML models
base_path = os.path.dirname(os.path.abspath(__file__))
models_path = os.path.join(base_path, "models")

url_model = None
text_model = None
tfidf = None

try:
    url_model = joblib.load(os.path.join(models_path, "url_model.joblib"))
    text_model = joblib.load(os.path.join(models_path, "text_model.joblib"))
    tfidf = joblib.load(os.path.join(models_path, "tfidf_vectorizer.joblib"))
except Exception as e:
    st.warning(f"Warning loading models: {e}. Local ML features will be disabled until models are available.")


# ------------------------------------------------------
# Sidebar Navigation
# ------------------------------------------------------
st.markdown("<div class='app-title'>AI Cyber Threat & Abuse Detector</div>", unsafe_allow_html=True)
st.sidebar.title("Threat Prediction")
st.sidebar.markdown("Quick tools — choose a page")
page = st.sidebar.radio("Navigate", ("URL Scanner", "Text Analyzer", "File Scanner", "IP Reputation", "Analytics Dashboard"))

st.sidebar.markdown("---")
st.sidebar.markdown("Final Year Project")
st.sidebar.markdown("Yusuf Ejaz, Prakash Kumar, Anmol Kumar, Narayan Mahato")


# Normalized logging helper (no rerun)

def save_scan_log(scan_type, input_data, result, confidence=0.0, raw=None):
    """
    Log scan in a normalized way. Return (ok: bool, msg: str).
    We avoid forcing a rerun so UI remains stable and results stay visible.
    """
    ts = datetime.utcnow().isoformat()
    try:
        # Attempt to pass timestamp and raw (if supported)
        log_scan(scan_type=scan_type, input_data=input_data, result=result, confidence=float(confidence), timestamp=ts, raw=raw)
        return True, "Logged successfully."
    except TypeError:
        try:
            log_scan(scan_type=scan_type, input_data=input_data, result=result, confidence=float(confidence))
            return True, "Logged successfully."
        except Exception as e:
            return False, f"Logging failed: {e}"
    except Exception as e:
        return False, f"Logging failed: {e}"


# ------------------
# URL Scanner Page
# ------------------
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
                st.markdown(f"<div class='result-box'><h3 style='color:{color}; margin:0;'>{label} — Confidence: {prob:.2f}</h3></div>", unsafe_allow_html=True)

                ok, msg = save_scan_log("URL", url, label, confidence=prob)
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
                with st.spinner("Submitting URL to VirusTotal and polling..."):
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
                            st.success("VirusTotal analysis completed.")
                            st.json(report)
                            stats = report.get("data", {}).get("attributes", {}).get("stats", {})
                            malicious = stats.get("malicious", 0) if stats else 0
                            total_votes = sum(stats.values()) if stats else 0
                            label = "⚠️ Malicious (VT)" if malicious > 0 else "✅ Clean (VT)"
                            st.markdown(f"**VT summary:** {label} — {malicious}/{total_votes} vendors flagged")
                            ok, msg = save_scan_log("URL (VT)", url, label, confidence=malicious, raw=report)
                            if ok:
                                st.success(msg)
                            else:
                                st.warning(msg)
                        else:
                            st.warning("No completed VT analysis yet. Try again in a moment.")
                    except Exception as e:
                        st.error(f"VirusTotal error: {e}")


# ------------------
# Text Analyzer Page
# ------------------
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


# ------------------
# File Scanner Page
# ------------------
elif page == "File Scanner":
    st.markdown("<div class='app-title'>📁 File Scanner (VirusTotal)</div>", unsafe_allow_html=True)
    st.markdown("<div class='muted'>Upload a file or paste a SHA256. The app checks VirusTotal and logs a summary (hash/result/confidence).</div>", unsafe_allow_html=True)

    uploaded = st.file_uploader("Drag & drop a file or click to browse", type=None)
    manual_hash = st.text_input("Or paste a SHA256 hash to lookup", placeholder="paste full sha256 here")

    # If user uploaded a file via the UI, show explicit "Find Result" button
    if uploaded:
        st.write(f"Uploaded: **{uploaded.name}** — {uploaded.size} bytes")
        if st.button("Find Result"):
            file_bytes = uploaded.read()
            file_hash = sha256_of_bytes(file_bytes)
            st.write("SHA256:", file_hash)
            if not VT_API_KEY:
                st.error("VT_API_KEY missing; add it to .env to use VT features.")
            else:
                try:
                    rep = vt_get_file_report_by_hash(file_hash)
                    if rep:
                        st.success("Found existing report.")
                        st.json(rep)
                        stats = rep.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                        malicious = stats.get("malicious", 0) if stats else 0
                        label = "⚠️ Malicious (VT)" if malicious > 0 else "✅ Clean (VT)"
                        ok, msg = save_scan_log("File", file_hash, label, confidence=malicious, raw=rep)
                        if ok:
                            st.success(msg)
                        else:
                            st.warning(msg)
                    else:
                        st.warning("No existing report. Uploading file to VirusTotal...")
                        try:
                            upload_resp = vt_upload_file(file_bytes, filename=uploaded.name)
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
                                st.success("Analysis completed.")
                                st.json(final_analysis)
                                stats = final_analysis.get("data", {}).get("attributes", {}).get("stats", {})
                                malicious = stats.get("malicious", 0) if stats else 0
                                label = "⚠️ Malicious (VT)" if malicious > 0 else "✅ Clean (VT)"
                                ok, msg = save_scan_log("File", file_hash, label, confidence=malicious, raw=final_analysis)
                                if ok:
                                    st.success(msg)
                                else:
                                    st.warning(msg)
                            else:
                                st.warning("Analysis not complete. Try again later.")
                        except Exception as e:
                            st.error(f"VirusTotal upload error: {e}")
                except Exception as e:
                    st.error(f"VirusTotal error: {e}")

    # Manual hash lookup button
    if manual_hash and st.button("Lookup Hash"):
        hash_val = manual_hash.strip()
        if not hash_val:
            st.warning("Paste a SHA256 hash.")
        elif not VT_API_KEY:
            st.error("VT_API_KEY missing.")
        else:
            try:
                rep = vt_get_file_report_by_hash(hash_val)
                if rep:
                    st.success("Found report.")
                    st.json(rep)
                    stats = rep.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                    malicious = stats.get("malicious", 0) if stats else 0
                    label = "⚠️ Malicious (VT)" if malicious > 0 else "✅ Clean (VT)"
                    ok, msg = save_scan_log("File", hash_val, label, confidence=malicious, raw=rep)
                    if ok:
                        st.success(msg)
                    else:
                        st.warning(msg)
                else:
                    st.warning("No report exists for that hash.")
            except Exception as e:
                st.error(f" Error: {e}")


# ------------------
# IP Reputation Page
# ------------------
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
                if ok:
                    st.success(msg)
                else:
                    st.warning(msg)


# ------------------
# Analytics Dashboard Page (New)
# ------------------
elif page == "Analytics Dashboard":
    st.markdown("<div class='app-title'>📊 Analytics Dashboard</div>", unsafe_allow_html=True)
    st.markdown("<div class='muted'>Upload a CSV/JSON with scan results (or drop one below). The dashboard will visualize fields such as result counts, confidence distribution, top hosts, or any numeric column you choose.</div>", unsafe_allow_html=True)

    uploaded_analytics = st.file_uploader("Upload CSV or JSON (scan logs export) to visualize", type=["csv", "json"] , key="analytics_uploader")

    # Provide sample data download button (if user wants to see format)
    if st.button("Show sample format for analytics"):
        sample = pd.DataFrame({
            "timestamp": [datetime.utcnow().isoformat()],
            "scan_type": ["URL"],
            "input_data": ["https://example.com"],
            "result": ["✅ Safe"],
            "confidence": [0.12]
        })
        st.dataframe(sample)
        csv = sample.to_csv(index=False)
        st.download_button("Download sample CSV", csv, file_name="analytics_sample.csv")

    if uploaded_analytics:
        try:
            if uploaded_analytics.type == "application/json" or uploaded_analytics.name.lower().endswith('.json'):
                df = pd.read_json(uploaded_analytics)
            else:
                df = pd.read_csv(uploaded_analytics)

            st.success(f"Loaded {len(df)} rows.")

            # Basic column info
            st.write("### Columns detected:")
            st.write(list(df.columns))

            # Allow user to pick columns for visualization
            numeric_cols = df.select_dtypes(include=["number"]).columns.tolist()
            cat_cols = df.select_dtypes(include=["object"]).columns.tolist()

            c1, c2 = st.columns(2)
            with c1:
                chart_type = st.selectbox("Chart type", ["Bar (counts)", "Pie (counts)", "Histogram / Distribution", "Line (time series)"])
                if chart_type in ["Bar (counts)", "Pie (counts)"]:
                    cat_col = st.selectbox("Categorical column (counts)", options=cat_cols if cat_cols else ["result"], index=0 if "result" in cat_cols else 0)
                elif chart_type == "Histogram / Distribution":
                    num_col = st.selectbox("Numeric column (distribution)", options=numeric_cols if numeric_cols else [])
                else:
                    # Line/Time series
                    time_col = st.selectbox("Time column (for x axis)", options=[col for col in df.columns if 'time' in col.lower() or 'date' in col.lower()] or df.columns.tolist())
                    val_col = st.selectbox("Value column (for y axis)", options=numeric_cols or [])

            with c2:
                st.write("")
                st.write("")
                if st.checkbox("Show raw preview (first 20 rows)"):
                    st.dataframe(df.head(20))

            # Draw charts
            try:
                if chart_type == "Bar (counts)":
                    counts = df[cat_col].value_counts().reset_index()
                    counts.columns = [cat_col, "count"]
                    fig = px.bar(counts, x=cat_col, y="count", title=f"Counts by {cat_col}")
                    st.plotly_chart(fig, use_container_width=True)

                elif chart_type == "Pie (counts)":
                    counts = df[cat_col].value_counts().reset_index()
                    counts.columns = [cat_col, "count"]
                    fig = px.pie(counts, names=cat_col, values="count", title=f"Distribution of {cat_col}")
                    st.plotly_chart(fig, use_container_width=True)

                elif chart_type == "Histogram / Distribution":
                    fig = px.histogram(df, x=num_col, nbins=40, title=f"Distribution of {num_col}")
                    st.plotly_chart(fig, use_container_width=True)

                elif chart_type == "Line (time series)":
                    # try to coerce time column
                    try:
                        df_copy = df.copy()
                        df_copy[time_col] = pd.to_datetime(df_copy[time_col])
                        df_sorted = df_copy.sort_values(time_col)
                        fig = px.line(df_sorted, x=time_col, y=val_col, title=f"{val_col} over {time_col}")
                        st.plotly_chart(fig, use_container_width=True)
                    except Exception as e:
                        st.error(f"Could not build time series: {e}")

            except Exception as e:
                st.error(f"Charting error: {e}")

        except Exception as e:
            st.error(f"Failed to read uploaded file: {e}")


# End of app
