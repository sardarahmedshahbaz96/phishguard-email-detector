# ============================================================
# phishing_cli.py
# Interactive Command Line Tool
# Allows the user to paste any email and get instant analysis
# Information Assurance - Term Project
# ============================================================

from phishing_detector import PhishingDetector


def get_multiline_input():
    """
    Takes multi-line input from the user.
    Input stops when the user enters a blank line.
    """
    print("(Paste the email below. Press Enter on a blank line when done.)")
    print("-" * 55)

    lines = []
    while True:
        line = input()
        if line == "":  # Stop reading when a blank line is entered
            break
        lines.append(line)

    return "\n".join(lines)


def main():
    """
    Main interactive loop.
    The user can analyze multiple emails one by one until they choose to exit.
    """
    print("\n" + "=" * 55)
    print("    PHISHING EMAIL DETECTOR - Interactive Tool")
    print("    Information Assurance - Term Project")
    print("=" * 55)

    while True:
        print("\nOptions:")
        print("  1. Analyze an email")
        print("  2. Exit")
        print("-" * 55)

        choice = input("Enter choice (1 or 2): ").strip()

        if choice == "1":
            print("\nPaste your email content below:")
            email_text = get_multiline_input()

            # Check if the user entered anything
            if not email_text.strip():
                print("[!] No email entered. Please try again.")
                continue

            # Create a detector object and print the report
            detector = PhishingDetector(email_text)
            print(detector.generate_report())

        elif choice == "2":
            print("\nExiting. Stay vigilant against phishing attacks.")
            break

        else:
            print("[!] Invalid choice. Please enter 1 or 2.")


# Entry point - this runs when you execute: python phishing_cli.py
if __name__ == "__main__":
    main()
