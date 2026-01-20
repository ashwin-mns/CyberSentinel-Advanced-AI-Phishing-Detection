import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score
import pickle

def generate_synthetic_data(n_samples=5000):
    """
    Generates synthetic data for training the model based on heuristics.
    Includes advanced & ultra-advanced features.
    """
    data = {
        # Basic
        'url_length': [], 'ssl': [], 'domain_age': [],
        # Advanced
        'has_ip': [], 'has_at': [], 'subdomain_count': [], 'has_hyphen': [],
        # Ultra-Advanced
        'has_double_slash': [], 'has_custom_port': [], 
        'tld_in_subdomain': [], 'suspicious_tld': [], 'high_numeric_ratio': [],
        'label': []
    }
    
    for _ in range(n_samples):
        is_phishing = np.random.choice([0, 1])
        
        if is_phishing:
            data['label'].append(1)
            # Heuristics for Phishing
            data['url_length'].append(np.random.randint(40, 200)) # Longer
            data['ssl'].append(np.random.choice([0, 1], p=[0.7, 0.3])) # Often missing
            data['domain_age'].append(np.random.randint(0, 60)) # New
            
            data['has_ip'].append(np.random.choice([0, 1], p=[0.9, 0.1])) 
            data['has_at'].append(np.random.choice([0, 1], p=[0.9, 0.1]))
            data['subdomain_count'].append(np.random.randint(2, 7)) # Complex
            data['has_hyphen'].append(np.random.choice([0, 1], p=[0.4, 0.6]))
            
            # Ultra Advanced
            data['has_double_slash'].append(np.random.choice([0, 1], p=[0.9, 0.1]))
            data['has_custom_port'].append(np.random.choice([0, 1], p=[0.9, 0.1]))
            data['tld_in_subdomain'].append(np.random.choice([0, 1], p=[0.8, 0.2])) # Very common trick
            data['suspicious_tld'].append(np.random.choice([0, 1], p=[0.8, 0.2]))
            data['high_numeric_ratio'].append(np.random.choice([0, 1], p=[0.7, 0.3])) # Random tokens
            
        else:
            data['label'].append(0)
            # Heuristics for Safe
            data['url_length'].append(np.random.randint(15, 60)) # Short
            data['ssl'].append(1) # Almost always SSL
            
            # 10% chance that Whois fails for legitimate sites (privacy protection etc)
            if np.random.random() < 0.1:
                data['domain_age'].append(-1)
            else:
                data['domain_age'].append(np.random.randint(365, 10000)) # Old
            
            data['has_ip'].append(0)
            data['has_at'].append(0)
            data['subdomain_count'].append(np.random.randint(1, 3))
            data['has_hyphen'].append(np.random.choice([0, 1], p=[0.8, 0.2]))
            
            # Ultra Advanced
            data['has_double_slash'].append(0)
            data['has_custom_port'].append(0)
            data['tld_in_subdomain'].append(0) 
            data['suspicious_tld'].append(0)
            data['high_numeric_ratio'].append(0) # Logic urls are usually words
            
    return pd.DataFrame(data)

def train_and_save_model():
    print("Generating comprehensive forensic dataset...")
    df = generate_synthetic_data(5000)
    
    features = [
        'url_length', 'ssl', 'domain_age',
        'has_ip', 'has_at', 'subdomain_count', 'has_hyphen',
        'has_double_slash', 'has_custom_port', 'tld_in_subdomain', 'suspicious_tld', 'high_numeric_ratio'
    ]
    
    X = df[features]
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    print(f"Training on {len(features)} distinct features...")
    model = RandomForestClassifier(n_estimators=200, random_state=42) # Increased trees for complexity
    model.fit(X_train, y_train)
    
    predictions = model.predict(X_test)
    accuracy = accuracy_score(y_test, predictions)
    print(f"Forensic Model Accuracy: {accuracy:.4f}")
    
    with open('phishing_model.pkl', 'wb') as f:
        pickle.dump(model, f)
    print("Model saved to phishing_model.pkl")

if __name__ == "__main__":
    train_and_save_model()
