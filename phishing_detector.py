# ============================================================
# phishing_detector.py
# Phishing Email Detection and Scoring Tool
# Information Assurance - Term Project
# ============================================================

# RUBRIC: List of red flags with their point values and keywords
# Each rule has a name, points (how suspicious it is), and keywords to search for
RUBRIC = [
    {
        "name": "Suspicious Sender Address",
        "points": 20,
        "keywords": ["paypa1", "arnazon", "g00gle", "micros0ft", "@gmail.com", "@yahoo.com", "@hotmail.com"]
    },
    {
        "name": "Urgency or Threat Language",
        "points": 15,
        "keywords": ["act immediately", "24 hours", "account will be closed", "urgent", "immediate action",
                     "verify now", "limited time", "expire", "suspended", "warning"]
    },
    {
        "name": "Poor Grammar or Spelling",
        "points": 15,
        "keywords": ["kindly do the needful", "dear valued costumer", "plese", "recieve", "acount",
                     "pasword", "beleive", "occured", "securty"]
    },
    {
        "name": "Generic Greeting",
        "points": 10,
        "keywords": ["dear customer", "dear user", "dear account holder", "dear client", "hello user"]
    },
    {
        "name": "Suspicious Link",
        "points": 20,
        "keywords": ["bit.ly", "tinyurl", "click here", "http://", "verify-login", "secure-update",
                     "account-confirm", "login-verify"]
    },
    {
        "name": "Request for Sensitive Information",
        "points": 15,
        "keywords": ["enter your password", "provide your ssn", "credit card number", "bank account",
                     "confirm your password", "enter your pin", "social security"]
    },
    {
        "name": "Unexpected Attachment",
        "points": 5,
        "keywords": [".exe", ".zip", ".docm", "open the attachment", "see attached file", "download the file"]
    }
]


# ============================================================
# PhishingDetector Class
# This class takes an email text as input and analyzes it.
# It returns a risk score between 0 and 100.
# Higher score = higher chance the email is a phishing attempt.
# ============================================================
class PhishingDetector:

    def __init__(self, email_text):
        # Convert email to lowercase so keyword matching is not case-sensitive
        self.email_text = email_text.lower()
        self.score = 0
        self.flagged_issues = []  # Stores which red flags were found

    def analyze(self):
        """
        Checks the email against each rule in the rubric.
        Adds points for every red flag found.
        Returns the total score and list of flagged issues.
        """
        self.score = 0
        self.flagged_issues = []

        # Go through each rule one by one
        for rule in RUBRIC:
            found_keywords = []

            # Check if any keyword from this rule exists in the email
            for keyword in rule["keywords"]:
                if keyword in self.email_text:
                    found_keywords.append(keyword)

            # If at least one keyword matched, add the points for this rule
            if found_keywords:
                self.score += rule["points"]
                self.flagged_issues.append({
                    "flag": rule["name"],
                    "points": rule["points"],
                    "matched_keywords": found_keywords
                })

        # Cap the score at 100
        if self.score > 100:
            self.score = 100

        return self.score, self.flagged_issues

    def get_risk_level(self):
        """
        Returns a risk label based on the score.
        Score 70-100 = HIGH RISK
        Score 40-69  = MEDIUM RISK
        Score 0-39   = LOW RISK
        """
        if self.score >= 70:
            return "HIGH RISK - Likely Phishing"
        elif self.score >= 40:
            return "MEDIUM RISK - Suspicious Email"
        else:
            return "LOW RISK - Probably Safe"

    def generate_report(self):
        """
        Builds and returns a formatted text report showing:
        - Total score
        - Risk level
        - List of red flags found
        - Recommended actions
        """
        score, issues = self.analyze()
        risk = self.get_risk_level()

        report = []
        report.append("=" * 55)
        report.append("        PHISHING EMAIL ANALYSIS REPORT")
        report.append("=" * 55)
        report.append(f"  Total Risk Score : {score} / 100")
        report.append(f"  Risk Level       : {risk}")
        report.append("=" * 55)

        if issues:
            report.append("\n  RED FLAGS DETECTED:")
            report.append("-" * 55)
            for i, issue in enumerate(issues, 1):
                report.append(f"\n  {i}. {issue['flag']}  (+{issue['points']} pts)")
                report.append(f"     Matched: {', '.join(issue['matched_keywords'])}")
        else:
            report.append("\n  No red flags detected in this email.")

        report.append("\n" + "=" * 55)
        report.append("  RECOMMENDED ACTION")
        report.append("-" * 55)

        if score >= 70:
            report.append("  [!] Do NOT click any links in this email.")
            report.append("  [!] Do NOT provide any personal information.")
            report.append("  [*] Report this email as phishing to your email provider.")
            report.append("  [*] Delete this email immediately.")
        elif score >= 40:
            report.append("  [!] Exercise caution with this email.")
            report.append("  [!] Verify the sender before clicking any links.")
            report.append("  [*] Contact the organization directly if unsure.")
        else:
            report.append("  [*] This email appears to be safe.")
            report.append("  [*] Always remain cautious with unknown senders.")

        report.append("=" * 55)
        return "\n".join(report)
