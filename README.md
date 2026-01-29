# 🛡️ CyberSentinel: Advanced AI Phishing Detection

A state-of-the-art phishing detection system powered by **Auto-Selected Machine Learning** and heuristic forensic analysis. This tool trains and evaluates multiple algorithms (**Random Forest, Decision Tree, KNN, and Ensemble**) to automatically select the most accurate model for real-time threat detection.

## 🚀 Features

### 🧠 Intelligent Model Selection
*   **Multi-Model Training**: Automatically trains 4 different models:
    *   **Random Forest** (Ensemble of decision trees)
    *   **Decision Tree** (Interpretable rules)
    *   **K-Nearest Neighbors (KNN)** (Distance-based classification)
    *   **Voting Ensemble** (Combines the power of all three)
*   **Auto-Tuning**: Evaluates each model on a test set and automatically saves the highest-performing one for production use.

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
    This command will train all 4 models, compare their accuracy, and save the winner to `phishing_model.pkl`.
    ```bash
    python train_model.py
    ```

## 🖥️ Usage

Run the web interface:
```bash
python -m streamlit run app.py
```

Enter any URL to see a real-time **Forensic DNA** breakdown of the site's security posture.

## 🧪 Logic & Scoring
The system uses a hybrid approach:
*   **ML Prediction**: The selected best model predicts the probability of phishing based on 12 feature vectors.
*   **Forensic Safety Checks**: Even if the ML predicts "Safe", the system will flag "Malicious" if critical heuristics (like IP usage or Double Slash) are detected.
*   **Visual Feedback**:
    *   **Green (Safe)**: High confidence, valid SSL, trusted domain age.
    *   **Red (Malicious)**: Probable phishing or presence of critical forensic flags.
    *   **Grey (Unknown)**: Whois lookup failed; requires manual caution.

## 🔧 Troubleshooting
*   **"Model not found"**: Ensure you have run `python train_model.py` at least once.
*   **"Domain Age: Unknown"**: This means the Whois server blocked the request. The model treats this as neutral/cautionary.

<img width="1919" height="849" alt="Screenshot 2026-01-29 175712" src="https://github.com/user-attachments/assets/dd6369f9-cb92-418e-8560-5a199fd5fce4" />

<img width="1900" height="855" alt="Screenshot 2026-01-29 175726" src="https://github.com/user-attachments/assets/24cb373f-b3bd-43b9-96f5-814935eab604" />

<img width="1918" height="853" alt="Screenshot 2026-01-29 175815" src="https://github.com/user-attachments/assets/998f1c2c-3a92-4c49-a8b9-6ce0a5d7d588" />

<img width="1908" height="854" alt="Screenshot 2026-01-29 175806" src="https://github.com/user-attachments/assets/c6105af0-3f2c-4046-af90-2582c713e6a3" />

