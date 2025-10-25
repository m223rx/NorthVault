import random, string


def generate_password(
    length=12, uppercase=True, lowercase=True, numbers=True, symbols=True
):
    chars = ""
    if uppercase:
        chars += string.ascii_uppercase
    if lowercase:
        chars += string.ascii_lowercase
    if numbers:
        chars += string.digits
    if symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?/"
    return "".join(random.choice(chars) for _ in range(length))
