from flask import Flask, render_template, request, jsonify
import re
import socket
import ssl
from urllib.parse import urlparse

app = Flask(__name__)

class PhishingRiskScorer:
    def __init__(self, url):
        self.url = url.strip()
        if not self.url.startswith(('http://', 'https://')):
            self.normalized_url = 'http://' + self.url
        else:
            self.normalized_url = self.url
            
        self.parsed_url = urlparse(self.normalized_url)
        self.domain = (self.parsed_url.netloc or self.parsed_url.path.split('/')[0]).lower()
        self.score = 0
        self.reasons = []

    def analyze(self):
        # Trusted Domains Whitelist
        trusted_domains = ['google.com', 'github.com', 'microsoft.com', 'apple.com', 'github.io']
        is_trusted = any(self.domain == td or self.domain.endswith('.' + td) for td in trusted_domains)

        if is_trusted:
            self.score = 0
            self.reasons.append("Domain belongs to a globally trusted and verified organization whitelist.")
        else:
            # 1. IP Address Check
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            if re.match(ip_pattern, self.domain):
                self.score += 25
                self.reasons.append("Hostname uses a direct IP address instead of a domain name (High Risk)")

            # 2. Tunneling / Dynamic DNS Service Check (Added loclx.io here!)
            tunnel_providers = ['trycloudflare.com', 'ngrok-free.app', 'ngrok.io', 'loca.lt', 'serveo.net', 'loclx.io', 'pinggy.link']
            if any(self.domain.endswith(provider) for provider in tunnel_providers):
                self.score += 40
                self.reasons.append(f"Domain uses a dynamic tunneling service often abused for credential phishing ({self.domain})")

            # 3. Excessive Hyphens / Subdomain Obfuscation
            hyphen_count = self.domain.count('-')
            if hyphen_count >= 3:
                self.score += 20
                self.reasons.append(f"Domain contains excessive hyphens often used to mimic legitimate brands ({hyphen_count} hyphens)")

            # 4. URL Length Check
            if len(self.url) > 75:
                self.score += 15
                self.reasons.append("URL length exceeds standard safety threshold (>75 characters)")

            # 5. @ Symbol Redirection Check
            if '@' in self.url:
                self.score += 25
                self.reasons.append("URL contains '@' symbol indicating user redirection obfuscation")

            # 6. Phishing Keywords & TLDs Check
            suspicious_keywords = ['login', 'verify', 'update', 'secure', 'auth', 'banking', 'account']
            lower_url = self.url.lower()
            has_keyword = any(kw in lower_url for kw in suspicious_keywords)
            has_suspicious_tld = self.domain.endswith(('.tk', '.xyz', '.ml', '.ga'))

            if has_keyword or has_suspicious_tld:
                self.score += 25
                self.reasons.append("Contains sensitive authentication keywords or suspicious TLD vector")

            # 7. HTTPS / SSL Check
            if self.parsed_url.scheme != 'https':
                self.score += 10
                self.reasons.append("Unencrypted connection protocol (HTTP)")
            else:
                self.reasons.append("Note: Valid SSL certificate detected (Phishing actors frequently exploit free SSL certificates)")

        # Classification
        risk_level = "LOW RISK (SAFE)"
        if self.score >= 45:
            risk_level = "HIGH RISK (PHISHING LIKELY)"
        elif self.score >= 20:
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
