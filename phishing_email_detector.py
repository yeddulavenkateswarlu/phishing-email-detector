import re

PHISHING_KEYWORDS = [
    "urgent", "verify your account", "click here", "login immediately",
    "password expired", "bank alert", "confirm details",
    "account suspended", "free reward", "limited time"
]

SUSPICIOUS_DOMAINS = ["bit.ly", "tinyurl", ".ru", ".cn"]

def detect_phishing(email_text):
    score = 0
    findings = []
    text = email_text.lower()

    for keyword in PHISHING_KEYWORDS:
        if keyword in text:
            score += 1
            findings.append(f"Suspicious keyword: {keyword}")

    urls = re.findall(r'https?://\S+', text)
    for url in urls:
        for domain in SUSPICIOUS_DOMAINS:
            if domain in url:
                score += 2
                findings.append(f"Suspicious URL: {url}")

    verdict = "PHISHING EMAIL DETECTED" if score >= 3 else "EMAIL APPEARS SAFE"
    return verdict, findings

if __name__ == "__main__":
    email = input("Paste email content:\n")
    verdict, details = detect_phishing(email)
    print("\nResult:", verdict)
    for d in details:
        print("-", d)
