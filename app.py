from flask import Flask, render_template, request
import re

app = Flask(__name__)

# ------------------------------
# Detection Functions (same logic)
# ------------------------------

def detect_suspicious_links(text):
    indicators = []
    url_pattern = r'(https?://[^\s]+)'
    urls = re.findall(url_pattern, text)

    suspicious_tlds = ['.xyz', '.top', '.click', '.info', '.support', '.online', '.site']

    for url in urls:
        if re.search(r'https?://\d{1,3}(\.\d{1,3}){3}', url):
            indicators.append(f"IP-based URL detected: {url}")

        if any(url.lower().endswith(tld) for tld in suspicious_tlds):
            indicators.append(f"Suspicious top-level domain: {url}")

        if "xn--" in url.lower():
            indicators.append(f"Punycode domain detected: {url}")

    return indicators

def detect_spoofed_addresses(text):
    indicators = []
    email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
    emails = re.findall(email_pattern, text)

    high_trust_domains = ["apple.com", "google.com", "microsoft.com", "bankofamerica.com"]

    for email in emails:
        domain = email.split("@")[-1]

        for legit in high_trust_domains:
            if domain.lower() != legit and sum(a != b for a, b in zip(domain.lower(), legit)) <= 2:
                indicators.append(f"Spoofed email: {email} (similar to {legit})")

    return indicators


def detect_urgent_language(text):
    urgent_keywords = [
        r"urgent", r"immediately", r"action required",
        r"verify now", r"your account will be closed",
        r"final notice", r"suspended", r"unauthorized activity"
    ]

    found = []
    for keyword in urgent_keywords:
        if re.search(keyword, text, re.IGNORECASE):
            found.append(f"Urgent phrase: '{keyword}'")

    return found


def analyze_text(content):
    results = []
    results += detect_suspicious_links(content)
    results += detect_spoofed_addresses(content)
    results += detect_urgent_language(content)
    return results


# ------------------------------
# Routes
# ------------------------------

@app.route("/", methods=["GET", "POST"])
def index():
    results = []
    text = ""

    if request.method == "POST":
        text = request.form.get("email_text")
        results = analyze_text(text)

    return render_template("index.html", results=results, text=text)

from flask import jsonify

@app.route("/analyze", methods=["POST"])
def analyze_api():
    data = request.json
    content = data.get("text", "")
    results = analyze_text(content)
    return jsonify({"results": results})

if __name__ == "__main__":
    app.run(debug=True)