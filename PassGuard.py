import math 
import secrets 
import string 
import re

THRESHOLDS = [
    (100, 10, "Excellent"), (80, 9, "Strong"), (60, 7, "Good"),
    (50, 6, "Fair"), (36, 4, "Weak"), (28, 2, "Very Weak"), (0, 1, "Fragile")
]
COMMON_WEAK = ["123456", "password", "admin", "welcome", "qwerty", "root", "12345678"]
LEET = {'a': '@4', 'e': '3', 'i': '1!', 'o': '0', 's': '$5', 't': '7', 'l': '1', 'g': '9', 'b': '8'}


def calculate_entropy(password):
    if not password: return 0
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, string.punctuation]
    size = sum(len(p) for p in pools if any(c in p for c in password))
    return len(password) * math.log2(size) if size else 0


def get_strength_score(entropy):
    for limit, score, _ in THRESHOLDS:
        if entropy >= limit: return score
    return 1


def get_strength_label(score):
    labels = {10: "Excellent", 9: "Strong", 7: "Good", 6: "Fair", 4: "Weak"}
    return next((v for k, v in labels.items() if score >= k), "Very Weak")


def estimate_crack_time(entropy):
    if entropy == 0: return "Instantly"
    seconds = (2 ** entropy) / 10_000_000_000
    units = [("million years", 31536000000000), ("thousand years", 31536000000),
             ("years", 31536000), ("months", 2592000), ("days", 86400), ("hours", 3600)]
    for name, div in units:
        if seconds >= div: return f"{seconds / div:.1f} {name}"
    return "Less than 1 minute"


def detect_patterns(password):
    weaknesses = []
    checks = [
        (r'(012|123|789)', "Number sequence"),
        (r'(abc|def|xyz)', "Letter sequence"),
        (r'(.)\1{2,}', "Repeated characters"),
        (r'(19|20)\d{2}', "Year pattern")
    ]
    for reg, msg in checks:
        if re.search(reg, password.lower()): weaknesses.append(msg)
    if password.isdigit(): weaknesses.append("All numbers")
    return weaknesses


def check_weak_password(password):
    pwd = password.lower()
    if pwd in COMMON_WEAK: return True, "Exact match"
    for weak in COMMON_WEAK:
        if len(weak) > 4 and weak in pwd: return True, f"Contains '{weak}'"
    if any(is_leet_variation(password, w) for w in COMMON_WEAK[:10]):
        return True, "Leet speak variation"
    return False, None


def is_leet_variation(password, base_word):
    pwd = password.lower()
    for char, subs in LEET.items():
        for s in subs: pwd = pwd.replace(s, char)
    return base_word in pwd


def generate_secure_alternative():
    chars = string.ascii_letters + string.digits + string.punctuation
    pwd = [secrets.choice(string.ascii_lowercase), secrets.choice(string.ascii_uppercase),
           secrets.choice(string.digits), secrets.choice(string.punctuation)]
    pwd += [secrets.choice(chars) for _ in range(12)]
    secrets.SystemRandom().shuffle(pwd)
    return ''.join(pwd)


def validate_input(password):
    if not password: return False, "Empty password"
    if not (4 <= len(password) <= 128): return False, "Length must be 4-128"
    return True, None


def get_specific_recommendations(password, weaknesses, entropy, score):
    recs = []
    types = [(string.ascii_lowercase, "lowercase"), (string.ascii_uppercase, "uppercase"),
             (string.digits, "numbers"), (string.punctuation, "special characters")]
    for pool, name in types:
        if not any(c in pool for c in password): recs.append(f"Add {name}")
    if len(password) < 12: recs.append("Increase length to 12+")
    if weaknesses: recs.append("Avoid patterns")
    return recs


def audit_password(user_password):
    valid, err = validate_input(user_password)
    if not valid: return {'valid': False, 'error': err}

    is_weak, reason = check_weak_password(user_password)
    entropy = calculate_entropy(user_password) if not is_weak else 0
    score = get_strength_score(entropy) if not is_weak else 1

    return {
        'valid': True, 'password': user_password, 'critical_weakness': is_weak,
        'entropy': round(entropy, 2), 'score': score,
        'strength_label': get_strength_label(score) if not is_weak else "Critical",
        'crack_time': estimate_crack_time(entropy),
        'patterns': detect_patterns(user_password),
        'recommendations': get_specific_recommendations(user_password, detect_patterns(user_password), entropy, score),
        'suggested_alternative': generate_secure_alternative()
    }


def display_audit_results(result):
    print(f"\n{'=' * 30}\nREPORT\n{'=' * 30}")
    if not result['valid']:
        print(f"Error: {result['error']}");
        return
    print(f"Score: {result['score']}/10 ({result['strength_label']})")
    print(f"Crack Time: {result['crack_time']}")
    for r in result['recommendations']: print(f" * {r}")
    print(f"Alternative: {result['suggested_alternative']}\n")


if __name__ == "__main__":
    pwd = input("Enter password: ").strip()
    display_audit_results(audit_password(pwd))
