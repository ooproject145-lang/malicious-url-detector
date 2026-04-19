import time
import re
from urllib.parse import urlparse

import joblib
import streamlit as st
import tldextract


SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "secure",
    "account",
    "update",
    "bank",
    "confirm",
    "free",
    "gift",
    "alert",
    "urgent",
    "bonus",
    "claim",
    "signin",
    "payment",
]


def normalize_url(url: str) -> str:
    url = str(url).strip().lower()
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    return url


def has_ip_address(url: str) -> int:
    pattern = r"(http[s]?://)?(\d{1,3}\.){3}\d{1,3}"
    return 1 if re.search(pattern, url) else 0


def count_suspicious_words(url: str) -> int:
    count = 0
    for word in SUSPICIOUS_WORDS:
        if word in url:
            count += 1
    return count


def extract_features_from_url(url: str) -> list:
    url = normalize_url(url)
    parsed = urlparse(url)
    extracted = tldextract.extract(url)

    domain = extracted.domain if extracted.domain else ""
    subdomain = extracted.subdomain if extracted.subdomain else ""
    path = parsed.path if parsed.path else ""

    return [
        len(url),
        len(domain),
        len(path),
        len(subdomain),
        url.count("."),
        url.count("-"),
        url.count("_"),
        url.count("/"),
        url.count("?"),
        url.count("="),
        url.count("@"),
        url.count("&"),
        sum(char.isdigit() for char in url),
        sum(char.isalpha() for char in url),
        1 if parsed.scheme == "https" else 0,
        has_ip_address(url),
        len([part for part in subdomain.split(".") if part]),
        count_suspicious_words(url),
    ]


@st.cache_resource
def load_model():
    return joblib.load("models/url_model.pkl")


def get_risk_level(confidence: float, prediction: int) -> str:
    if prediction == 0:
        return "Low Risk"
    if confidence >= 90:
        return "High Risk"
    if confidence >= 70:
        return "Moderate Risk"
    return "Suspicious"


def get_result_class(prediction: int) -> str:
    return "result-danger" if prediction == 1 else "result-safe"


def get_result_icon(prediction: int) -> str:
    return "🚨" if prediction == 1 else "🛡️"


def get_result_label(prediction: int) -> str:
    return "Malicious URL" if prediction == 1 else "Legitimate URL"


def get_risk_color(prediction: int, confidence: float) -> str:
    if prediction == 0:
        return "#52ffa8"
    if confidence >= 90:
        return "#ff7676"
    if confidence >= 70:
        return "#ffd166"
    return "#f4a261"


def feature_summary(url: str) -> dict:
    normalized = normalize_url(url)
    parsed = urlparse(normalized)
    extracted = tldextract.extract(normalized)
    subdomain = extracted.subdomain if extracted.subdomain else ""

    return {
        "Suspicious Words": count_suspicious_words(normalized),
        "Special Symbols": normalized.count("@") + normalized.count("?") + normalized.count("=") + normalized.count("&"),
        "Subdomains": len([part for part in subdomain.split(".") if part]),
        "Uses HTTPS": "Yes" if parsed.scheme == "https" else "No",
    }


def get_scan_message(prediction: int, confidence: float) -> str:
    if prediction == 1 and confidence >= 90:
        return "This URL shows strong malicious indicators. Avoid interacting with it."
    if prediction == 1:
        return "This URL appears suspicious and should be treated with caution."
    return "This URL appears legitimate based on the current lightweight analysis."


model = load_model()

st.set_page_config(
    page_title="Malicious URL Detector",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background:
        radial-gradient(circle at 10% 10%, rgba(0,255,140,0.12), transparent 25%),
        radial-gradient(circle at 90% 12%, rgba(0,255,200,0.08), transparent 22%),
        radial-gradient(circle at 50% 100%, rgba(30,255,140,0.08), transparent 30%),
        linear-gradient(135deg, #02130d 0%, #04271b 40%, #073625 70%, #0a4732 100%);
    color: #f5fff8;
}

.block-container {
    max-width: 1250px;
    padding-top: 3.3rem;
    padding-bottom: 2rem;
}

section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #02170f 0%, #05261a 45%, #083322 100%) !important;
    border-right: 1px solid rgba(124,255,178,0.16);
}

section[data-testid="stSidebar"] > div {
    background: linear-gradient(180deg, #02170f 0%, #05261a 45%, #083322 100%) !important;
}

@media (max-width: 768px) {
    section[data-testid="stSidebar"] {
        background: #042116 !important;
        border-right: 1px solid rgba(124,255,178,0.18);
    }

    section[data-testid="stSidebar"] > div {
        background: #042116 !important;
    }

    .block-container {
        padding-top: 2.4rem;
        padding-left: 1rem;
        padding-right: 1rem;
    }

    .main-title {
        font-size: 2.3rem !important;
        margin-top: 0.4rem !important;
    }

    .sub-text {
        font-size: 0.95rem !important;
        margin-bottom: 1.2rem !important;
    }

    .student-card,
    .hero-card,
    .info-card,
    .sample-card,
    .summary-card,
    .metric-card,
    .feature-mini-card {
        margin-bottom: 1rem !important;
    }
}

@keyframes titleShimmer {
    0% { background-position: 0% 50%; }
    100% { background-position: 200% 50%; }
}

@keyframes softFloat {
    0% { transform: translateY(0px); }
    50% { transform: translateY(-5px); }
    100% { transform: translateY(0px); }
}

@keyframes glowPulse {
    0% { box-shadow: 0 0 0 rgba(121,255,176,0.05); }
    50% { box-shadow: 0 0 24px rgba(121,255,176,0.16); }
    100% { box-shadow: 0 0 0 rgba(121,255,176,0.05); }
}

@keyframes slideUp {
    from {
        opacity: 0;
        transform: translateY(18px);
    }
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

.main-title {
    text-align: center;
    font-size: 3.4rem;
    font-weight: 900;
    line-height: 1.15;
    margin-top: 0.8rem;
    margin-bottom: 0.55rem;
    background: linear-gradient(90deg, #7dffb4, #ffffff, #7dffb4, #c7ffe3);
    background-size: 200% auto;
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    animation: titleShimmer 5s linear infinite;
}

.sub-text {
    text-align: center;
    font-size: 1.08rem;
    color: #dcffeb;
    margin-bottom: 1.7rem;
    animation: slideUp 0.8s ease-out;
}

.hero-card,
.student-card,
.info-card,
.sample-card,
.metric-card,
.feature-mini-card,
.sidebar-glow-card,
.status-card,
.summary-card,
.progress-shell {
    background: rgba(255,255,255,0.055);
    border: 1px solid rgba(121,255,176,0.18);
    backdrop-filter: blur(10px);
    box-shadow: 0 10px 28px rgba(0,0,0,0.12);
}

.student-card {
    border-radius: 24px;
    padding: 1.35rem;
    margin-bottom: 1.2rem;
    animation: slideUp 0.9s ease-out;
    position: relative;
    overflow: hidden;
}

.student-card::before,
.hero-card::before,
.info-card::before,
.metric-card::before,
.sample-card::before,
.summary-card::before {
    content: "";
    position: absolute;
    inset: 0;
    background: linear-gradient(120deg, transparent 0%, rgba(255,255,255,0.06) 50%, transparent 100%);
    transform: translateX(-100%);
    transition: transform 0.9s ease;
    pointer-events: none;
}

.student-card:hover::before,
.hero-card:hover::before,
.info-card:hover::before,
.metric-card:hover::before,
.sample-card:hover::before,
.summary-card:hover::before {
    transform: translateX(100%);
}

.student-name {
    font-size: 1.28rem;
    font-weight: 800;
    color: #f0fff6;
    margin-bottom: 0.55rem;
}

.student-meta {
    color: #d8ffe7;
    line-height: 1.75;
    font-size: 1rem;
}

.hero-card {
    border-radius: 22px;
    padding: 1.25rem 1.35rem;
    min-height: 170px;
    position: relative;
    overflow: hidden;
    animation: glowPulse 4s infinite ease-in-out;
}

.info-card {
    border-radius: 22px;
    padding: 1.25rem;
    min-height: 170px;
    position: relative;
    overflow: hidden;
    animation: softFloat 4.3s ease-in-out infinite;
    margin-bottom: 1.2rem;
}

.sample-card {
    border-radius: 22px;
    padding: 1.2rem;
    min-height: 170px;
    position: relative;
    overflow: hidden;
    margin-top: 0.2rem;
}

.status-card {
    border-radius: 18px;
    padding: 0.95rem 1rem;
    margin-top: 0.9rem;
    margin-bottom: 0.9rem;
    color: #effff5;
    font-weight: 700;
    animation: slideUp 0.5s ease-out;
}

.summary-card {
    border-radius: 22px;
    padding: 1.2rem;
    margin-top: 1rem;
    position: relative;
    overflow: hidden;
    animation: slideUp 0.6s ease-out;
}

.result-safe,
.result-danger {
    padding: 1rem 1.15rem;
    border-radius: 18px;
    font-size: 1.08rem;
    font-weight: 800;
    margin-top: 0.9rem;
    animation: slideUp 0.5s ease-out;
    letter-spacing: 0.2px;
}

.result-safe {
    background: linear-gradient(90deg, rgba(20,120,60,0.22), rgba(40,160,90,0.08));
    border: 1px solid #53ffab;
    color: #effff5;
}

.result-danger {
    background: linear-gradient(90deg, rgba(180,30,30,0.22), rgba(140,20,20,0.08));
    border: 1px solid #ff7676;
    color: #fff1f1;
}

.risk-badge {
    display: inline-block;
    margin-top: 0.85rem;
    margin-bottom: 1rem;
    padding: 0.58rem 1rem;
    border-radius: 999px;
    font-weight: 800;
    color: #f6fff9;
    background: rgba(255,255,255,0.06);
    animation: glowPulse 3.8s ease-in-out infinite;
}

.progress-shell {
    border-radius: 18px;
    padding: 1rem;
    margin-top: 0.8rem;
    margin-bottom: 1rem;
}

.progress-title {
    font-size: 0.98rem;
    font-weight: 700;
    color: #eafff2;
    margin-bottom: 0.65rem;
}

.progress-track {
    width: 100%;
    height: 16px;
    background: rgba(255,255,255,0.08);
    border-radius: 999px;
    overflow: hidden;
    border: 1px solid rgba(121,255,176,0.18);
}

.progress-fill {
    height: 100%;
    border-radius: 999px;
    transition: width 0.5s ease;
}

.metric-card {
    border-radius: 22px;
    padding: 1.2rem;
    text-align: center;
    min-height: 130px;
    transition: transform 0.28s ease, box-shadow 0.28s ease, border-color 0.28s ease;
    position: relative;
    overflow: hidden;
}

.metric-card:hover {
    transform: translateY(-7px) scale(1.01);
    box-shadow: 0 16px 34px rgba(0,0,0,0.17), 0 0 20px rgba(121,255,176,0.10);
    border-color: rgba(121,255,176,0.35);
}

.metric-icon {
    font-size: 1.4rem;
    margin-bottom: 0.15rem;
}

.metric-title {
    font-size: 1rem;
    color: #d8ffea;
    margin-bottom: 0.45rem;
    font-weight: 600;
}

.metric-value {
    font-size: 1.6rem;
    font-weight: 900;
    color: #ffffff;
}

.feature-mini-card {
    border-radius: 18px;
    padding: 1rem;
    text-align: center;
    min-height: 110px;
    transition: transform 0.25s ease, box-shadow 0.25s ease;
    margin-top: 0.2rem;
}

.feature-mini-card:hover {
    transform: translateY(-5px);
    box-shadow: 0 12px 22px rgba(0,0,0,0.14);
}

.feature-mini-title {
    color: #d7ffea;
    font-size: 0.92rem;
    margin-bottom: 0.4rem;
    font-weight: 600;
}

.feature-mini-value {
    color: white;
    font-size: 1.25rem;
    font-weight: 800;
}

.sidebar-title {
    font-size: 1.65rem;
    font-weight: 800;
    color: #f2fff7;
}

.sidebar-glow-card {
    border-radius: 18px;
    padding: 1rem;
    margin-top: 0.8rem;
    animation: glowPulse 4s infinite ease-in-out;
}

.footer-note {
    text-align: center;
    color: #dbffea;
    opacity: 0.92;
    margin-top: 2rem;
    font-size: 0.95rem;
    line-height: 1.8;
}

div.stButton > button {
    background: linear-gradient(90deg, #17c56f, #0ea85c);
    color: white;
    border: none;
    border-radius: 14px;
    padding: 0.84rem 1.2rem;
    font-size: 1rem;
    font-weight: 800;
    width: 100%;
    transition: all 0.25s ease;
}

div.stButton > button:hover {
    color: white;
    transform: translateY(-2px);
    box-shadow: 0 12px 24px rgba(0,0,0,0.16);
}

div[data-baseweb="input"] > div {
    background-color: rgba(255,255,255,0.08);
    border-radius: 14px;
}

div[data-baseweb="input"] input {
    color: #ffffff !important;
}

.stTextInput label {
    color: #effff5 !important;
    font-weight: 700;
}

hr {
    border-color: rgba(121,255,176,0.12);
}
</style>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown('<div class="sidebar-title">🛡️ Control Panel</div>', unsafe_allow_html=True)
    st.markdown("Analyze URL structure and identify suspicious web resources using a lightweight neural network model.")

    st.markdown(
        """
        <div class="sidebar-glow-card">
            <strong>✨ App Highlights</strong><br><br>
            • Real-time URL scan<br>
            • Lightweight model<br>
            • Cloud-ready deployment<br>
            • Interactive result dashboard
        </div>
        """,
        unsafe_allow_html=True
    )

    st.markdown("---")
    st.subheader("📌 Model Details")
    st.write("**Model:** MLPClassifier")
    st.write("**Features:** URL lexical + structural")
    st.write("**Status:** Streamlit Cloud ready")

    st.markdown("---")
    st.subheader("🧪 Sample URLs")
    st.code("google.com")
    st.code("github.com")
    st.code("verify-your-bank-account-now.ru")
    st.code("login-paypal-security-update.xyz")

st.markdown('<div class="main-title">Malicious URL Detector</div>', unsafe_allow_html=True)
st.markdown(
    '<div class="sub-text">A lightweight neural network based system for real-time malicious web resource identification</div>',
    unsafe_allow_html=True
)

st.markdown(
    """
    <div class="student-card">
        <div class="student-name">🎓 Student Project Profile</div>
        <div class="student-meta">
            <strong>Name:</strong> Amina Abubakar Abba-Kura<br>
            <strong>Matric Number:</strong> MIU/22/CMP/CYB/178<br>
            <strong>Department:</strong> Department of Cyber Security<br>
            <strong>Faculty:</strong> Computing Faculty<br>
            <strong>Institution:</strong> Mewar International University, Nigeria
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

top_left, top_right = st.columns([2, 1], gap="large")

with top_left:
    st.markdown(
        """
        <div class="hero-card">
            <h3 style="margin-bottom:0.55rem; color:#eefff5;">⚙️ System Overview</h3>
            <p style="line-height:1.8; color:#d7ffea; margin:0;">
                This lightweight intelligent system extracts important lexical and structural features
                from a URL and applies a trained neural network model to classify the resource
                as legitimate or malicious in near real time.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

with top_right:
    st.markdown(
        """
        <div class="info-card">
            <h3 style="margin-bottom:0.55rem; color:#eefff5;">🎯 Detection Focus</h3>
            <p style="line-height:1.8; color:#d7ffea; margin:0;">
                The model checks suspicious keywords, URL length, symbols, subdomains,
                and special patterns commonly associated with phishing and deceptive websites.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

input_col, help_col = st.columns([2, 1], gap="large")

with input_col:
    url_input = st.text_input(
        "Enter a URL to scan",
        placeholder="e.g. login-paypal-security-update.xyz"
    )
    scan_clicked = st.button("🔍 Scan URL")

with help_col:
    st.markdown(
        """
        <div class="sample-card">
            <h3 style="margin-bottom:0.6rem; color:#eefff5;">🚀 Quick Test Guide</h3>
            <p style="color:#d8ffe8; line-height:1.8; margin:0;">
                Try safe samples like <strong>google.com</strong> or <strong>github.com</strong>.<br><br>
                Try suspicious samples like <strong>verify-your-bank-account-now.ru</strong> or
                <strong>login-paypal-security-update.xyz</strong>.
            </p>
        </div>
        """,
        unsafe_allow_html=True
    )

if scan_clicked:
    if not url_input.strip():
        st.warning("Please enter a URL first.")
    else:
        with st.spinner("Scanning URL and analyzing features..."):
            start_time = time.time()
            features = extract_features_from_url(url_input)
            prediction = model.predict([features])[0]
            probabilities = model.predict_proba([features])[0]
            elapsed_time = time.time() - start_time

        confidence = max(probabilities) * 100
        risk_level = get_risk_level(confidence, prediction)
        risk_color = get_risk_color(prediction, confidence)

        result_class = get_result_class(prediction)
        result_icon = get_result_icon(prediction)
        result_label = get_result_label(prediction)
        scan_message = get_scan_message(prediction, confidence)

        st.markdown(
            f'<div class="{result_class}">{result_icon} Prediction Result: {result_label}</div>',
            unsafe_allow_html=True
        )

        status_bg = "rgba(20,120,60,0.18)" if prediction == 0 else "rgba(180,30,30,0.18)"
        status_border = "#53ffab" if prediction == 0 else "#ff7676"

        st.markdown(
            f'''
            <div class="status-card" style="background:{status_bg}; border:1px solid {status_border};">
                📡 Scan Status: Completed successfully. {scan_message}
            </div>
            ''',
            unsafe_allow_html=True
        )

        st.markdown(
            f'<div class="risk-badge" style="border:1px solid {risk_color};">📍 Risk Level: {risk_level}</div>',
            unsafe_allow_html=True
        )

        st.markdown(
            f'''
            <div class="progress-shell">
                <div class="progress-title">Confidence Level</div>
                <div class="progress-track">
                    <div class="progress-fill" style="width:{confidence:.2f}%; background:linear-gradient(90deg, {risk_color}, #7dffb4);"></div>
                </div>
            </div>
            ''',
            unsafe_allow_html=True
        )

        col1, col2, col3 = st.columns(3, gap="large")

        with col1:
            st.markdown(
                f'''
                <div class="metric-card">
                    <div class="metric-icon">🎯</div>
                    <div class="metric-title">Confidence</div>
                    <div class="metric-value">{confidence:.2f}%</div>
                </div>
                ''',
                unsafe_allow_html=True
            )

        with col2:
            st.markdown(
                f'''
                <div class="metric-card">
                    <div class="metric-icon">⚡</div>
                    <div class="metric-title">Response Time</div>
                    <div class="metric-value">{elapsed_time:.4f}s</div>
                </div>
                ''',
                unsafe_allow_html=True
            )

        with col3:
            st.markdown(
                f'''
                <div class="metric-card">
                    <div class="metric-icon">🔗</div>
                    <div class="metric-title">Input URL Length</div>
                    <div class="metric-value">{len(url_input)}</div>
                </div>
                ''',
                unsafe_allow_html=True
            )

        st.markdown("<br>", unsafe_allow_html=True)

        summary = feature_summary(url_input)
        f1, f2, f3, f4 = st.columns(4, gap="large")

        with f1:
            st.markdown(
                f'''
                <div class="feature-mini-card">
                    <div class="feature-mini-title">🧠 Suspicious Words</div>
                    <div class="feature-mini-value">{summary["Suspicious Words"]}</div>
                </div>
                ''',
                unsafe_allow_html=True
            )

        with f2:
            st.markdown(
                f'''
                <div class="feature-mini-card">
                    <div class="feature-mini-title">🔣 Special Symbols</div>
                    <div class="feature-mini-value">{summary["Special Symbols"]}</div>
                </div>
                ''',
                unsafe_allow_html=True
            )

        with f3:
            st.markdown(
                f'''
                <div class="feature-mini-card">
                    <div class="feature-mini-title">🌐 Subdomains</div>
                    <div class="feature-mini-value">{summary["Subdomains"]}</div>
                </div>
                ''',
                unsafe_allow_html=True
            )

        with f4:
            st.markdown(
                f'''
                <div class="feature-mini-card">
                    <div class="feature-mini-title">🔒 Uses HTTPS</div>
                    <div class="feature-mini-value">{summary["Uses HTTPS"]}</div>
                </div>
                ''',
                unsafe_allow_html=True
            )

        st.markdown(
            f'''
            <div class="summary-card">
                <h3 style="margin-bottom:0.55rem; color:#eefff5;">📝 Scan Summary</h3>
                <p style="line-height:1.8; color:#d7ffea; margin:0;">
                    The submitted URL <strong>{url_input}</strong> was analyzed using the trained lightweight neural network model.
                    Based on the extracted lexical and structural indicators, the system classified it as
                    <strong>{result_label}</strong> with a confidence level of <strong>{confidence:.2f}%</strong>.
                </p>
            </div>
            ''',
            unsafe_allow_html=True
        )

st.markdown(
    '''
    <div class="footer-note">
        Built with Python, Scikit-learn, Streamlit, and lightweight URL-based feature engineering.<br>
        Final Year Project Interface for Amina Abubakar Abba-Kura, MIU/22/CMP/CYB/178.
    </div>
    ''',
    unsafe_allow_html=True
)