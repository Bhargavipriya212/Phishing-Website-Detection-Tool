import pandas as pd
import re
from urllib.parse import urlparse

# Define suspicious keywords
SUSPICIOUS_KEYWORDS = ['login', 'verify', 'bank', 'update', 'secure', 'ebayisapi', 'free', 'confirm', 'password']

# Feature extraction for one URL
def extract_features(url):
    parsed = urlparse(url)
    hostname = parsed.hostname or ""
    
    return {
        "url_length": len(url),
        "has_ip": int(bool(re.search(r'(\d{1,3}\.){3}\d{1,3}', hostname))),
        "has_https": int(url.lower().startswith("https://")),
        "count_dots": url.count('.'),
        "count_hyphens": url.count('-'),
        "count_at": url.count('@'),
        "has_suspicious_keyword": int(any(word in url.lower() for word in SUSPICIOUS_KEYWORDS))
    }

# Rule-based phishing detector
def is_phishing_url(url):
    features = extract_features(url)
    score = (
        features["has_ip"]
        + features["count_at"]
        + features["has_suspicious_keyword"]
        + (1 if features["url_length"] > 75 else 0)
        + (1 if features["count_dots"] > 5 else 0)
        + (1 if features["count_hyphens"] > 4 else 0)
        + (0 if features["has_https"] else 1)
    )
    return score >= 3  # Flag as phishing if score exceeds threshold

# Load dataset from CSV (optional)
def scan_csv(file_path):
    df = pd.read_csv(file_path)
    df['phishing'] = df['url'].apply(is_phishing_url)
    print(df[['url', 'phishing']])
    df.to_csv("rule_based_results.csv", index=False)
    print("\n Results saved to rule_based_results.csv")

# Interactive scanner
def scan_interactively():
    while True:
        url = input("\nEnter a URL (or 'exit' to quit): ").strip()
        if url.lower() == "exit":
            break
        result = is_phishing_url(url)
        print("Phishing URL!" if result else "Legitimate URL")

# Main
if __name__ == "__main__":
    print("=== Rule-Based URL Phishing Detector ===")
    mode = input("Choose mode (1: interactive | 2: scan CSV): ")

    if mode == "1":
        scan_interactively()
    elif mode == "2":
        csv_file = input("Enter CSV file path (with 'url' column): ").strip()
        scan_csv(csv_file)
    else:
        print("Invalid option.")
