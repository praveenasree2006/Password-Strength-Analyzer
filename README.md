# Password-Strength-Analyzer
Developed a Python-based Password Strength Checker that evaluates password length, complexity, and uniqueness. It detects weak or reused passwords, generates stronger alternatives, and uses SHA-256 hashing for secure password history storage, promoting cybersecurity best practices and secure authentication.
import re
import hashlib
import random
import string
import json
import os

PASSWORD_DB = "password_history.json"

# Load old passwords
def load_passwords():
    if os.path.exists(PASSWORD_DB):
        with open(PASSWORD_DB, "r") as file:
            return json.load(file)
    return []

# Save password hash
def save_password(password):
    passwords = load_passwords()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()

    if hashed_password not in passwords:
        passwords.append(hashed_password)

        with open(PASSWORD_DB, "w") as file:
            json.dump(passwords, file)

# Check password reuse
def is_reused(password):
    passwords = load_passwords()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password in passwords

# Password strength evaluation
def evaluate_password(password):
    score = 0
    feedback = []

    # Length Check
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Password should be at least 8 characters long.")

    # Uppercase Check
    if re.search(r"[A-Z]", password):
        score += 1
    else:
        feedback.append("Add uppercase letters.")

    # Lowercase Check
    if re.search(r"[a-z]", password):
        score += 1
    else:
        feedback.append("Add lowercase letters.")

    # Number Check
    if re.search(r"\d", password):
        score += 1
    else:
        feedback.append("Add numbers.")

    # Special Character Check
    if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        score += 2
    else:
        feedback.append("Add special characters.")

    # Uniqueness Check
    if is_reused(password):
        feedback.append("Password has been used before.")
        score -= 2

    # Strength Rating
    if score >= 7:
        strength = "Very Strong"
    elif score >= 5:
        strength = "Strong"
    elif score >= 3:
        strength = "Moderate"
    else:
        strength = "Weak"

    return strength, feedback

# Generate strong password suggestion
def generate_strong_password(length=14):
    characters = (
        string.ascii_uppercase +
        string.ascii_lowercase +
        string.digits +
        "!@#$%^&*"
    )

    password = ''.join(random.choice(characters) for _ in range(length))
    return password

# Main Program
def main():
    print("=" * 50)
    print("PASSWORD STRENGTH CHECKER")
    print("=" * 50)

    password = input("Enter a password: ")

    strength, feedback = evaluate_password(password)

    print(f"\nPassword Strength: {strength}")

    if feedback:
        print("\nSuggestions:")
        for item in feedback:
            print(f"- {item}")

    if strength in ["Weak", "Moderate"]:
        print("\nSuggested Strong Password:")
        print(generate_strong_password())

    if not is_reused(password):
        save_choice = input("\nSave this password to history? (y/n): ").lower()
        if save_choice == 'y':
            save_password(password)
            print("Password saved successfully.")
    else:
        print("\nThis password already exists in history.")

if __name__ == "__main__":
    main()
