from flask import Flask, render_template, request, jsonify
import re
import socket
import ssl
from urllib.parse import urlparse

app = Flask(__name__)

class PhishingRiskScorer:
    def __init__(self, url):
        self.url = url
        if not url.startswith(('http://', 'https://')):
            self.normalized_url = 'http://' + url
        else:
            self.normalized_url = url
            
        self.parsed_url = urlparse(self.normalized_url)
        self.domain = self.parsed_url.netloc or self.parsed_url.path.split('/')[0]
        self.score = 0
        self.reasons = []

    def analyze(self):
        # 1. IP Address Check
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, self.domain):
            self.score += 25
            self.reasons.append("Hostname uses a direct IP address instead of a domain name (High Risk)")

        # 2. URL Length Check
        if len(self.url) > 75:
            self.score += 15
            self.reasons.append("URL length exceeds standard safety threshold (>75 characters)")

        # 3. @ Symbol Redirection Check
        if '@' in self.url:
            self.score += 25
            self.reasons.append("URL contains '@' symbol indicating user redirection obfuscation")

        # 4. Phishing Keywords & TLDs Check
        suspicious_keywords = ['login-verify', 'update-account', 'secure-auth', 'banking-update']
        if any(keyword in self.url.lower() for keyword in suspicious_keywords) or self.domain.endswith(('.tk', '.xyz', '.ml', '.ga')):
            self.score += 30
            self.reasons.append("Suspicious TLD or keyword pattern matching known phishing vectors")

        # 5. HTTPS / SSL Check
        if self.parsed_url.scheme != 'https':
            self.score += 15
            self.reasons.append("Unencrypted connection protocol (HTTP)")
        else:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((self.domain, 443), timeout=2) as sock:
                    with context.wrap_socket(sock, server_hostname=self.domain) as ssock:
                        pass
            except Exception:
                self.score += 20
                self.reasons.append("Invalid or unverified SSL certificate on HTTPS connection")

        # Classification
        risk_level = "LOW RISK (SAFE)"
        if self.score >= 50:
            risk_level = "HIGH RISK (PHISHING LIKELY)"
        elif self.score >= 25:
            risk_level = "MEDIUM RISK (SUSPICIOUS)"

        return {
            "domain": self.domain,
            "score": f"{self.score}/100",
            "classification": risk_level,
            "flags": self.reasons if self.reasons else ["No obvious anomaly or phishing indicators identified."]
        }

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_url():
    data = request.get_json()
    target_url = data.get('url', '').strip()
    
    if not target_url:
        return jsonify({"error": "No URL provided"}), 400

    scorer = PhishingRiskScorer(target_url)
    results = scorer.analyze()
    
    return jsonify(results)

if __name__ == '__main__':
    app.run(debug=True, port=5000)