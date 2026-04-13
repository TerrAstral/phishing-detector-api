from flask import Flask, render_template, request, jsonify
import re

app = Flask(__name__)

# -----------------------------------
# Detection Functions
# -----------------------------------

def detect_suspicious_links(text):
    indicators = []

    url_pattern = r'(https?://[^\s]+)'
    urls = re.findall(url_pattern, text)

    suspicious_tlds = [
        '.xyz', '.top', '.click',
        '.info', '.support',
        '.online', '.site'
    ]

    for url in urls:

        if re.search(r'https?://\d+\.\d+\.\d+\.\d+', url):
            indicators.append("IP-based suspicious URL detected")

        if any(url.lower().endswith(tld) for tld in suspicious_tlds):
            indicators.append("Suspicious domain extension detected")

        if "xn--" in url.lower():
            indicators.append("Encoded / punycode domain detected")

    return indicators


def detect_spoofed_addresses(text):
    indicators = []

    email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
    emails = re.findall(email_pattern, text)

    trusted_domains = [
        "google.com",
        "apple.com",
        "microsoft.com",
        "bankofamerica.com"
    ]

    for email in emails:
        domain = email.split("@")[-1].lower()

        for legit in trusted_domains:
            if domain != legit:
                diff = sum(a != b for a, b in zip(domain, legit))
                if diff <= 2:
                    indicators.append(
                        f"Spoofed sender similar to {legit}"
                    )

    return indicators


def detect_urgent_language(text):
    indicators = []

    phrases = [
        "urgent",
        "verify now",
        "immediately",
        "final notice",
        "unauthorized activity",
        "account suspended",
        "action required",
        "your account will be closed"
        "win"
        "prize"
        "giveaway"
    ]

    for phrase in phrases:
        if phrase.lower() in text.lower():
            indicators.append(
                f"Urgent language detected: {phrase}"
            )

    return indicators


def analyze_text(text):

    if not text:
        return []

    results = []
    results += detect_suspicious_links(text)
    results += detect_spoofed_addresses(text)
    results += detect_urgent_language(text)

    return results


def risk_level(count):
    if count == 0:
        return "Low"
    elif count <= 2:
        return "Medium"
    else:
        return "High"


# -----------------------------------
# Web UI Route
# -----------------------------------

@app.route("/", methods=["GET", "POST"])
def index():

    results = []
    text = ""
    status = ""
    risk = ""

    if request.method == "POST":

        text = request.form.get("email_text", "").strip()

        if text:
            results = analyze_text(text)
            status = (
                "Likely phishing attempt"
                if results else
                "Likely safe"
            )
            risk = risk_level(len(results))

    return render_template(
        "index.html",
        results=results,
        text=text,
        status=status,
        risk=risk
    )


# -----------------------------------
# Gmail / API Route
# -----------------------------------

@app.route("/")
def home():
    return "Phishing Detector API Running"


@app.route("/analyze", methods=["POST"])
def analyze_api():

    data = request.get_json()

    if not data or "text" not in data:
        return jsonify({
            "error": "Missing text field"
        }), 400

    text = data["text"]

    results = analyze_text(text)

    return jsonify({
        "results": results,
        "count": len(results),
        "status": (
            "Likely phishing attempt"
            if results else
            "Likely safe"
        ),
        "risk": risk_level(len(results))
    })


# -----------------------------------

if __name__ == "__main__":
    app.run(debug=True)
