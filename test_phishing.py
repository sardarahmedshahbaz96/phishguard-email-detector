# ============================================================
# test_phishing.py
# Test Script - Analyzes 5 Sample Emails
# Information Assurance - Term Project
# ============================================================

from phishing_detector import PhishingDetector

# ============================================================
# SAMPLE EMAILS
# Email 1 and 3 and 5 are phishing emails (HIGH RISK)
# Email 2 and 4 are legitimate emails (LOW RISK)
# ============================================================

email_1 = """
From: support@paypa1.com
Subject: Your Account Has Been Suspended

Dear Customer,

Your PayPal account has been suspended due to suspicious activity.
You must verify your account within 24 hours or it will be permanently closed.

Click here to verify: http://verify-login.paypa1.com/secure

Enter your password and credit card number to restore access.

PayPal Security Team
"""

email_2 = """
From: hr@company.com
Subject: Meeting Tomorrow at 10 AM

Hi Sarah,

Just a reminder about our team meeting tomorrow at 10 AM in Conference Room B.
Please bring your project updates.

See you there!
Regards,
John
HR Department
"""

email_3 = """
From: alert@arnazon.com
Subject: URGENT: Your Amazon Order Problem

Dear valued costumer,

We have occured a problem with your recent order.
Immediate action required! Your account will be closed in 24 hours.

Please enter your password and bank account details at:
http://account-confirm.arnazon.com

Download the file for more details: invoice.exe

Act immediately!
Amazon Support
"""

email_4 = """
From: newsletter@healthtips.com
Subject: 5 Tips for Better Sleep

Hello,

Here are this week's top sleep tips from our health experts:
1. Avoid screens 1 hour before bed
2. Keep a consistent sleep schedule
3. Try herbal tea like chamomile

Unsubscribe anytime. View in browser: https://healthtips.com/newsletter

Best,
Health Tips Team
"""

email_5 = """
From: security@micros0ft.com
Subject: Warning: Suspicious Login Detected

Dear account holder,

We have detected a suspicious login to your Microsoft account.
Urgent: Verify your identity now or your account will be suspended.

Click here: bit.ly/ms-verify-login

Provide your password and social security number to confirm your identity.
Limited time to respond!

Microsoft Security
"""


# ============================================================
# TEST FUNCTION
# Loops through all 5 emails, creates a detector for each,
# and prints the full analysis report.
# ============================================================
def run_all_tests():
    # Store all emails with their labels in a list
    emails = [
        ("Email 1 - PayPal Account Suspension (Phishing)", email_1),
        ("Email 2 - Office Meeting Reminder (Legitimate)", email_2),
        ("Email 3 - Amazon Order Alert (Phishing)", email_3),
        ("Email 4 - Health Newsletter (Legitimate)", email_4),
        ("Email 5 - Microsoft Security Warning (Phishing)", email_5),
    ]

    print("\n" + "=" * 55)
    print("         PHISHING DETECTION - TEST RESULTS")
    print("=" * 55)

    # Analyze each email one by one
    for label, email_text in emails:
        print(f"\n>> Testing: {label}")

        # Create a detector object with the email text
        detector = PhishingDetector(email_text)

        # Print the full analysis report
        print(detector.generate_report())


# Entry point - this runs when you execute: python test_phishing.py
if __name__ == "__main__":
    run_all_tests()
