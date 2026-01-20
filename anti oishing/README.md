# 🛡️ CyberSentinel: Advanced AI Phishing Detection

A state-of-the-art phishing detection system powered by Machine Learning and heuristic forensic analysis. This tool utilizes a **Random Forest Classifier** trained on 12 distinct security features to identify malicious websites in real-time.

## 🚀 Features

### 🔍 Basic Analysis
*   **URL Length**: Detects suspiciously long URLs used to hide domains.
*   **SSL Certificate**: Checks for valid HTTPS connections.
*   **Domain Age**: Flags domains created recently (< 30 days) as high risk.

### 🧬 Advanced Forensics
*   **IP Address detection**: Flags raw IP hostnames (e.g., `http://192.168.1.1`).
*   **@ Symbol Redirection**: Detects authentication spoofing tricks.
*   **Subdomain Depth**: Analyzes complex subdomain structures used to mimic legitimate sites.
*   **Hyphenation**: Identifies typo-squatting attempts (e.g., `face-book.com`).

### 🔬 Ultra-Advanced Forensics
*   **Redirection Attacks (`//`)**: Detects open redirects in URL paths.
*   **Non-Standard Ports**: Flags custom ports (e.g., `:8080`) often used in attacks.
*   **TLD Injection**: Detects misleading TLDs inside subdomains (e.g., `paypal.com.fake-site.net`).
*   **Suspicious TLDs**: Warns against abuse-prone TLDs like `.tk`, `.xyz`, `.top`.
*   **Entropy Analysis**: Detects high randomness in URL strings (DGA).

## 🛠️ Installation

1.  **Clone the repository**:
    ```bash
    git clone <repository_url>
    ```

2.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

3.  **Train the AI Model** (Required for first run):
    ```bash
    python train_model.py
    ```

## 🖥️ Usage

Run the web interface:
```bash
streamlit run app.py
```

Enter any URL to see a real-time **Forensic DNA** breakdown of the site's security posture.

## 🧪 Logic & Scoring
The system uses a weighted probability model.
*   **Green (Safe)**: High confidence, valid SSL, trusted domain age.
*   **Red (Malicious)**: Presence of critical flags (IP, Redirects, TLD injection) or new domains.
*   **Grey (Unknown)**: Whois lookup failed; requires manual caution.

## 🔧 Troubleshooting
*   **"Domain Age: Unknown"**: This means the Whois server blocked the request. The model treats this as neutral/cautionary rather than immediately malicious.
