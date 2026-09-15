def check_length(password):
    """Return whether *password* meets the 15-character requirement and its verdict."""
    password_length = len(password)

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


def audit_password(account, username, password, rotation_interval):
    """Print one password audit and return its pass, fail, and critical deltas."""
    length_ok, length_verdict = check_length(password)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval)

    password_length = len(password)
    length_score = password_length * 10
    rotation_count = 36 / rotation_interval
    rotation_years = 3 / rotation_interval

    overall_pass = length_ok and has_digit and not_username and rotation_ok

    print('=' * 25)
    print('Account:' + account)
    print('Username:' + username)
    print('Password Length:', password_length, 'characters')
    print('Length Score:', length_score, 'points')
    print('Rotation Interval:', rotation_count, 'months')
    print('Rotations (3 yr):', rotation_years)
    print('-' * 25)

    if not_username is False:
        critical = 1
        print('CRITICAL — password must not match username.')
    else:
        critical = 0
        print('PASS Username and password do not match')

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
    batch_size = 3
    count = 0
    batch_count = 1
    total_pass = 0
    total_fail = 0
    critical_count = 0

    while count < batch_size:
        print('=' * 25)
        print('Password Audit Report (', batch_count, ' of 3)')
        print('=' * 25)
        account = input('What is your Gmail? ')
        username = input('What is your Username? ')
        password = input('What is your Password? ')
        rotation_interval_string = input('What is your Rotation Interval? ')
        rotation_interval = int(rotation_interval_string)

        passed, failed, critical = audit_password(
            account, username, password, rotation_interval
        )
        total_pass += passed
        total_fail += failed
        critical_count += critical
        count += 1
        batch_count += 1

    print('=' * 25)
    print('Batch Summary')
    print('=' * 25)
    print('Total passwords audited:', count)
    print('Total passed:', total_pass)
    print('Total failed:', total_fail)
    print('CRITICAL username-match flags:', critical_count)
    print('NOTE: Input is still hardcoded -- file reading coming in Week 08.')
    print('=' * 25)
