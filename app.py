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

        # Urgency / fear tactics
        "urgent",
        "verify now",
        "immediately",
        "final notice",
        "unauthorized activity",
        "account suspended",
        "action required",
        "your account will be closed",
        "limited time",
        "respond now",
        "security alert",
        "suspended account",
        "payment failed",
        "confirm identity",

        # Prize / giveaway phishing
        "congratulations",
        "you have won",
        "winner",
        "claim your prize",
        "claim now",
        "free gift",
        "gift card",
        "selected as winner",
        "exclusive reward",
        "cash prize",
        "jackpot",
        "lottery winner",
        "sweepstakes",
        "you are eligible",
        "reward waiting",
        "instant reward",
        "special promotion",
        "free vacation",
        "bonus reward",
        "claim your reward",
        "you've been selected",
        "free iphone",
        "free ipad",
        "free money",
        "guaranteed winner",
        "prize awaiting",

        # Financial bait
        "tax refund",
        "refund available",
        "stimulus payment",
        "bank transfer ready",
        "unclaimed funds",

        # Credential theft bait
        "login required",
        "reset password",
        "verify account",
        "update payment information"
    ]

    for phrase in phrases:
        if phrase.lower() in text.lower():
            indicators.append(
                f"Suspicious phrase detected: {phrase}"
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
