known_breached = [
    "password", "password123", "123456", "qwerty", "letmein",
    "welcome", "monkey", "dragon", "master", "sunshine",
]

policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True,
}


def check_length(password, policy):
    """Return whether *password* meets the policy length requirement and its verdict."""
    password_length = len(password)
    length_thresholds = (
        policy["min_length"],
        policy["strong_length"],
    )
    moderate_limit = sum(length_thresholds) // len(length_thresholds)

    if password_length < policy["min_length"]:
        length_verdict = 'WEAK — does not meet minimum length requirements'
    elif password_length <= moderate_limit:
        length_verdict = 'MODERATE — meets minimum but falls short of NIST recommendations'
    elif password_length < policy["strong_length"]:
        length_verdict = 'GOOD — acceptable length for most systems'
    else:
        length_verdict = 'STRONG — meets NIST SP 800-63B recommendations'

    length_ok = password_length >= policy["strong_length"]
    return length_ok, length_verdict


def check_digit(password):
    """Return True when *password* contains at least one ASCII digit."""
    has_digit = False
    for char in password:
        if char in '0123456789':
            has_digit = True

    return has_digit


def check_username(password, username):
    """Return True when the password is different from the username."""
    not_username = password != username
    return not_username


def check_rotation(rotation_interval, policy):
    """Return whether the rotation interval is acceptable and its verdict."""
    rotation_ok = rotation_interval <= policy["max_rotation_months"]

    if rotation_interval > policy["max_rotation_months"]:
        rotation_verdict = (
            'WARNING — rotation interval exceeds recommended maximum of '
            f'{policy["max_rotation_months"]} months'
        )
    elif rotation_interval >= policy["good_rotation_months"]:
        rotation_verdict = 'ACCEPTABLE — rotation interval within recommended range'
    else:
        rotation_verdict = 'EXCELLENT — frequent rotation policy detected'

    return rotation_ok, rotation_verdict


def check_breach(password, known_breached):
    """Return True when *password* is not in the known breached-password list."""
    not_breached = password not in known_breached
    return not_breached


def audit_password(account, username, password, rotation_interval, known_breached, policy):
    """Print one password audit and return its pass, fail, and critical deltas."""
    length_ok, length_verdict = check_length(password, policy)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval, policy)
    not_breached = check_breach(password, known_breached)

    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval
    rotation_years = 3 // rotation_interval

    overall_pass = length_ok and has_digit and not_username and not_breached
    critical = 1 if not_username is False or not_breached is False else 0

    print('=' * 25)
    print('Account:' + account)
    print('Username:' + username)
    print('Password Length:', password_length, 'characters')
    print('Length Score:', length_score, 'points')
    print('Rotation Interval:', rotation_count, 'months')
    print('Rotations (3 yr):', rotation_years)
    print('-' * 25)

    if not_username is False:
        print('CRITICAL — password must not match username.')
    else:
        print('PASS Username and password do not match')

    if not_breached:
        print('Breach check: PASS -- password not found in known breach list')
    else:
        print('Breach check: CRITICAL -- password found in known breach list')

    print(length_verdict)

    if has_digit:
        print('NOTE: A digit was found in the password.')
    else:
        print('NOTE: No digit was found in the password.')

    print('Rotation Verdict:', rotation_verdict)
    print('-' * 25)

    if overall_pass:
        passed = 1
        failed = 0
        print('OVERALL: PASS — password meets all checked criteria')
    else:
        passed = 0
        failed = 1
        print('OVERALL: FAIL — see findings above')

    print('=' * 25)
    return passed, failed, critical


if __name__ == '__main__':
    credentials = [
        {"account": "Gmail", "username": "jsmith", "password": "password123", "rotation_interval": 12},
        {"account": "SSH Server", "username": "jsmith", "password": "jsmith", "rotation_interval": 24},
        {"account": "VPN", "username": "jsmith", "password": "Tr0ub4dor&3correct", "rotation_interval": 3},
        {"account": "Company Email", "username": "jsmith", "password": "summer2024!", "rotation_interval": 6},
        {"account": "GitHub", "username": "jsmith", "password": "Blue-Harbor-72-Lantern", "rotation_interval": 6},
    ]

    batch_size = len(credentials)
    batch_count = 1
    summary = {
        "total": 0,
        "passed": 0,
        "failed": 0,
        "critical": 0,
        "failed_accounts": [],
        "critical_accounts": [],
    }

    for cred in credentials:
        print('=' * 25)
        print('Password Audit Report (', batch_count, ' of', batch_size, ')')
        print('=' * 25)

        passed, failed, critical = audit_password(
            cred["account"],
            cred["username"],
            cred["password"],
            cred["rotation_interval"],
            known_breached,
            policy,
        )
        summary["total"] += 1
        summary["passed"] += passed
        summary["failed"] += failed
        summary["critical"] += critical
        if failed == 1:
            summary["failed_accounts"].append(cred["account"])
        if critical == 1:
            summary["critical_accounts"].append(cred["account"])
        batch_count += 1

    print('=' * 25)
    print('Batch Summary')
    print('=' * 25)
    print('Total passwords audited:', summary.get("total", 0))
    print('Total passed:', summary.get("passed", 0))
    print('Total failed:', summary.get("failed", 0))
    print('Failed accounts:', summary.get("failed_accounts", []))
    print('CRITICAL accounts:', summary.get("critical", 0))
    print('Critical accounts:', summary.get("critical_accounts", []))
    print('NOTE: Credentials and breach list are hardcoded -- file reading coming in Week 07.')
    print('=' * 25)
