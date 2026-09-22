# Keep this outside the main guard so imported functions and tests can reuse the
# breach list without also running the interactive batch-audit code.
known_breached = [
    "password", "password123", "123456", "qwerty", "letmein",
    "welcome", "monkey", "dragon", "master", "sunshine",
]


def check_length(password):
    """Return whether *password* meets the 15-character requirement and its verdict."""
    # Calculate the length once because both the verdict and pass/fail result use it.
    password_length = len(password)

    # These ranges provide a detailed message even when the 15-character rule fails.
    if password_length < 8:
        length_verdict = 'WEAK — does not meet minimum length requirements'
    elif password_length <= 11:
        length_verdict = 'MODERATE — meets minimum but falls short of NIST recommendations'
    elif password_length <= 14:
        length_verdict = 'GOOD — acceptable length for most systems'
    else:
        length_verdict = 'STRONG — meets NIST SP 800-63B recommendations'

    length_ok = password_length >= 15
    return length_ok, length_verdict


def check_digit(password):
    """Return True when *password* contains at least one ASCII digit."""
    has_digit = False
    # Walk through each character because this check needs to inspect characters individually.
    for char in password:
        if char in '0123456789':
            has_digit = True

    return has_digit


def check_username(password, username):
    """Return True when the password is different from the username."""
    not_username = password != username
    return not_username


def check_rotation(rotation_interval):
    """Return whether the rotation interval is acceptable and its verdict."""
    rotation_ok = rotation_interval <= 12

    if rotation_interval > 12:
        rotation_verdict = 'WARNING — rotation interval exceeds recommended maximum of 12 months'
    elif rotation_interval >= 6:
        rotation_verdict = 'ACCEPTABLE — rotation interval within recommended range'
    else:
        rotation_verdict = 'EXCELLENT — frequent rotation policy detected'

    return rotation_ok, rotation_verdict


def check_breach(password, known_breached):
    """Return True when *password* is not in the known breached-password list."""
    # `in` checks whether the whole password is a list item; a `for` loop would
    # walk through the list one item at a time to make that comparison manually.
    not_breached = password not in known_breached
    return not_breached


def audit_password(account, username, password, rotation_interval, known_breached):
    """Print one password audit and return its pass, fail, and critical deltas."""
    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval)
    not_breached = check_breach(password, known_breached)

    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval
    rotation_years = 3 // rotation_interval

    # A password passes only when every required security check succeeds.
    overall_pass = length_ok and has_digit and not_username and not_breached
    # Matching the username or a breached password is treated as a critical finding.
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
        ["Gmail", "jsmith", "password123", 12],
        ["SSH Server", "jsmith", "jsmith", 24],
        ["VPN", "jsmith", "Tr0ub4dor&3correct", 3],
        ["Company Email", "jsmith", "summer2024!", 6],
        ["GitHub", "jsmith", "Blue-Harbor-72-Lantern", 6],
    ]

    batch_size = len(credentials)
    count = 0
    batch_count = 1
    total_pass = 0
    failed_accounts = []
    critical_accounts = []

    for record in credentials:
        # Pull the four fields from the current account record before auditing it.
        account = record[0]
        username = record[1]
        password = record[2]
        rotation_interval = record[3]

        print('=' * 25)
        print('Password Audit Report (', batch_count, ' of', batch_size, ')')
        print('=' * 25)

        passed, failed, critical = audit_password(
            account, username, password, rotation_interval, known_breached
        )
        total_pass += passed
        if failed == 1:
            failed_accounts.append(account)
        if critical == 1:
            critical_accounts.append(account)
        count += 1
        batch_count += 1

    print('=' * 25)
    print('Batch Summary')
    print('=' * 25)
    print('Total passwords audited:', count)
    print('Total passed:', total_pass)
    print('Total failed:', len(failed_accounts))
    print('Failed accounts:', failed_accounts)
    print('CRITICAL accounts:', len(critical_accounts))
    print('Critical accounts:', critical_accounts)
    print('NOTE: Breach list and credentials are hardcoded -- file reading coming in Week 08.')
    print('=' * 25)
