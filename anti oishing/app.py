import streamlit as st
import pandas as pd
import pickle
import utils
import os

# Page Config
st.set_page_config(
    page_title="Phishing Detection AI",
    page_icon="🛡️",
    layout="wide"
)

# Load Model
@st.cache_resource
def load_model():
    try:
        with open('phishing_model.pkl', 'rb') as f:
            model = pickle.load(f)
        return model
    except FileNotFoundError:
        return None

model = load_model()

# Custom CSS for Glassy Dark Theme
st.markdown("""
    <style>
    /* Main Background */
    .stApp {
        background: radial-gradient(circle at center, #1b2735 0%, #090a0f 100%);
        font-family: 'Inter', sans-serif;
    }
    
    /* Glassy Container */
    .glass-container {
        background: rgba(255, 255, 255, 0.03);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border-radius: 16px;
        border: 1px solid rgba(255, 255, 255, 0.08);
        padding: 24px;
        margin-bottom: 20px;
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.5);
    }
    
    /* Input Fields */
    .stTextInput > div > div > input {
        background-color: rgba(0, 0, 0, 0.3);
        color: #e0e0e0;
        border: 1px solid rgba(255, 255, 255, 0.1);
        border-radius: 8px;
        height: 50px;
        font-size: 1.1em;
    }
    .stTextInput > div > div > input:focus {
        border-color: #00bcd4;
        box-shadow: 0 0 10px rgba(0, 188, 212, 0.3);
    }
    
    /* Typography */
    h1, h2, h3, p, label { color: #e0e0e0 !important; }
    
    /* Alert Boxes */
    .alert-box {
        padding: 15px;
        border-radius: 8px;
        margin-bottom: 10px;
        font-weight: 500;
    }
    .alert-danger { background: rgba(255, 82, 82, 0.2); border: 1px solid #ff5252; color: #ff867c; }
    .alert-warning { background: rgba(255, 179, 0, 0.2); border: 1px solid #ffb300; color: #ffe57f; }
    .alert-success { background: rgba(0, 230, 118, 0.2); border: 1px solid #00e676; color: #69f0ae; }
    
    /* Analyze Button */
    .stButton > button {
        width: 100%;
        background: linear-gradient(135deg, #00C9FF 0%, #92FE9D 100%);
        color: #000;
        border: none;
        padding: 12px;
        font-weight: 700;
        font-size: 1.1em;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    .stButton > button:hover {
        transform: translateY(-2px);
        box-shadow: 0 5px 15px rgba(0, 201, 255, 0.4);
    }
    </style>
""", unsafe_allow_html=True)

# Header
col1, col2, col3 = st.columns([1, 6, 1])
with col2:
    st.markdown('<h1 style="text-align: center; margin-bottom: 0;">🛡️ CyberSentinel AI</h1>', unsafe_allow_html=True)
    st.markdown('<p style="text-align: center; color: #888; margin-top: 5px;">Advanced Phishing & Fraud Detection Engine</p>', unsafe_allow_html=True)

# Main Input Area
st.markdown('<div class="glass-container">', unsafe_allow_html=True)
url = st.text_input("Enter Suspicious Link:", placeholder="e.g., http://paypal-secure-login.com.update.tk/login")
analyze = st.button("RUN FORENSIC ANALYSIS")
st.markdown('</div>', unsafe_allow_html=True)

if analyze and url:
    with st.spinner("Decrypting URL structure & analyzing entropy..."):
        # 1. Feature Extraction
        f = {
            'url_length': utils.get_url_length(url),
            'ssl': utils.check_ssl(url),
            'domain_age': utils.get_domain_age(url),
            'has_ip': utils.has_ip_address(url),
            'has_at': utils.has_at_symbol(url),
            'subdomain_count': utils.count_subdomains(url),
            'has_hyphen': utils.has_hyphen(url),
            'has_double_slash': utils.has_double_slash(url),
            'has_custom_port': utils.has_custom_port(url),
            'tld_in_subdomain': utils.tld_in_subdomain(url),
            'suspicious_tld': utils.suspicious_tld(url),
            'high_numeric_ratio': utils.high_numeric_ratio(url)
        }
        
        # 2. Prediction
        input_data = pd.DataFrame([f])
        
        # --- Prediction Logic & Safety Override ---
        # Calculate Risk Score (number of bad flags)
        risk_flags = 0
        if f['has_ip']: risk_flags += 1
        if f['has_at']: risk_flags += 1
        if f['has_double_slash']: risk_flags += 1
        if f['has_custom_port']: risk_flags += 1
        if f['tld_in_subdomain']: risk_flags += 1
        if f['suspicious_tld']: risk_flags += 1
        if f['high_numeric_ratio']: risk_flags += 1
        if f['ssl'] == 0: risk_flags += 1
        if f['domain_age'] == 0: risk_flags += 1 # Only count 0 (New) as risk, not -1 (Unknown)
        
        # Prediction
        prediction_label = "SAFE"
        
        if model:
            ml_prediction = model.predict(input_data)[0]
            probability = model.predict_proba(input_data)[0][1]
            
            # HEURISTIC OVERRIDE: 
            # If ML predicts Phishing (1) BUT we found almost no forensic issues (Risk <= 1), 
            # we treat it as a False Positive (likely due to unknown domain age).
            if ml_prediction == 1:
                if risk_flags <= 1:
                    prediction_label = "SAFE" # Override
                else:
                    prediction_label = "PHISHING"
            else:
                prediction_label = "SAFE"

            # --- Results Display ---
            if prediction_label == "PHISHING":
                st.markdown(f"""
                <div class="glass-container" style="border-color: #ff5252; box-shadow: 0 0 20px rgba(255, 82, 82, 0.2);">
                    <h1 style="color: #ff5252 !important; text-align: center;">🚨 MALICIOUS DETECTED</h1>
                    <p style="text-align: center; font-size: 1.2em;">Confidence: {probability*100:.1f}%</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.markdown(f"""
                <div class="glass-container" style="border-color: #00e676; box-shadow: 0 0 20px rgba(0, 230, 118, 0.2);">
                    <h1 style="color: #00e676 !important; text-align: center;">✅ SAFE LINK</h1>
                    <p style="text-align: center; font-size: 1.2em;">No immediate threats found.</p>
                </div>
                """, unsafe_allow_html=True)

            # --- Forensic Dashboard ---
            st.markdown("### 🧬 Forensic DNA")
            
            # Divide into Logical Groups
            
            # Group 1: Structural Anomalies
            st.caption("STRUCTURAL ANOMALIES")
            c1, c2, c3, c4 = st.columns(4)
            with c1:
                if f['has_ip']: st.markdown('<div class="alert-box alert-danger">Raw IP Host</div>', unsafe_allow_html=True)
                else: st.markdown('<div class="alert-box alert-success">Standard Host</div>', unsafe_allow_html=True)
            with c2:
                if f['has_at']: st.markdown('<div class="alert-box alert-danger">@ Redirection</div>', unsafe_allow_html=True)
                else: st.markdown('<div class="alert-box alert-success">No @ Symbol</div>', unsafe_allow_html=True)
            with c3:
                if f['has_double_slash']: st.markdown('<div class="alert-box alert-danger">// Redirection</div>', unsafe_allow_html=True)
                else: st.markdown('<div class="alert-box alert-success">Path Clean</div>', unsafe_allow_html=True)
            with c4:
                if f['has_custom_port']: st.markdown('<div class="alert-box alert-danger">Non-Std Port</div>', unsafe_allow_html=True)
                else: st.markdown('<div class="alert-box alert-success">Standard Port</div>', unsafe_allow_html=True)

            # Group 2: Domain Obfuscation
            st.caption("DOMAIN OBFUSCATION")
            c5, c6, c7, c8 = st.columns(4)
            with c5:
                if f['tld_in_subdomain']: st.markdown('<div class="alert-box alert-danger">TLD in Subdomain</div>', unsafe_allow_html=True)
                else: st.markdown('<div class="alert-box alert-success">Subdomain Safe</div>', unsafe_allow_html=True)
            with c6:
                if f['suspicious_tld']: st.markdown('<div class="alert-box alert-warning">Suspicious TLD</div>', unsafe_allow_html=True)
                else: st.markdown('<div class="alert-box alert-success">Common TLD</div>', unsafe_allow_html=True)
            with c7:
                if f['high_numeric_ratio']: st.markdown('<div class="alert-box alert-warning">High Entropy</div>', unsafe_allow_html=True)
                else: st.markdown('<div class="alert-box alert-success">Low Entropy</div>', unsafe_allow_html=True)
            with c8:
                if f['has_hyphen']: st.markdown('<div class="alert-box alert-warning">Hyphenated</div>', unsafe_allow_html=True)
                else: st.markdown('<div class="alert-box alert-success">No Hyphens</div>', unsafe_allow_html=True)

            # Group 3: Technical Metadata
            st.caption("TECHNICAL METADATA")
            m1, m2, m3 = st.columns(3)
            
            # Domain Age Logic: Handle -1 (Unknown) separately from 0 (New)
            if f['domain_age'] == -1:
                 m1.metric("Domain Age", "Unknown", delta_color="off", help="Whois lookup failed. Common for some TLDs.")
            else:
                age_label = "New (<1 Mo)" if f['domain_age'] < 30 else f"{f['domain_age']} Days"
                color = "inverse" if f['domain_age'] < 30 else "normal"
                m1.metric("Domain Age", age_label, delta_color=color)
            
            m2.metric("SSL Status", "Valid" if f['ssl'] else "Invalid", delta_color="normal" if f['ssl'] else "inverse")
            m3.metric("Subdomain Depth", f"{f['subdomain_count']}", delta_color="inverse" if f['subdomain_count'] > 3 else "normal")

        else:
            st.error("AI Model not found or corrupted. Please retrain.")

# Footer
st.markdown("---")
st.markdown('<p style="text-align: center; color: #555; font-size: 0.8em;">Developed for Advanced Security Analysis</p>', unsafe_allow_html=True)
