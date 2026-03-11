# Password Strength Checker
# This program checks the strength of a password based on certain criteria.
def check_password_strength(password):
    issues = []
    if len(password) < 8:
        issues.append("Password must be at least 8 characters long.")
    if not any(char.isupper() for char in password):
        issues.append("Password must contain at least one uppercase letter.")   
    if not any(char.islower() for char in password):
        issues.append("Password must contain at least one lowercase letter.")   
    if not any(char.isdigit() for char in password):
        issues.append("Password must contain at least one digit.")
    if not any(char in "!@#$%^&*()-_=+[]{}|;:'\",.<>?/" for char in password):
        issues.append("Password must contain at least one special character.")  
    if len(issues) == 0:
        return "Password is strong."
    else:
        return "Password is not strong. Issues found:\n" + "\n".join(issues)
password = input("Enter a password to check its strength: ")
result = check_password_strength(password)
print(result)
