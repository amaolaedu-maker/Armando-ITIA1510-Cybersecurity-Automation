policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True,
}


def load_breached(filepath):
    """Read the breached password file. Returns a list of password strings."""
    known_breached = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line != "":
                known_breached.append(line)
    return known_breached


def load_credentials(filepath):
    """Read the credentials file. Returns a list of credential dictionaries."""
    credentials = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line == "":
                continue

            fields = line.split(",")
            credentials.append({
                "account": fields[0],
                "username": fields[1],
                "password": fields[2],
                "rotation_interval": int(fields[3]),
            })
    return credentials


def write_report(report_lines, filepath):
    """Write each string in report_lines to the file as one line."""
    with open(filepath, "w", encoding="utf-8") as f:
        for line in report_lines:
            f.write(line + "\n")


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


def audit_password(account, username, password, rotation_interval, known_breached, policy, report_lines):
    """Append one password audit to report_lines and return its pass, fail, and critical deltas."""
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

    report_lines.append('=' * 25)
    report_lines.append('Account:' + account)
    report_lines.append('Username:' + username)
    report_lines.append(f'Password Length: {password_length} characters')
    report_lines.append(f'Length Score: {length_score} points')
    report_lines.append(f'Rotation Interval: {rotation_count} months')
    report_lines.append(f'Rotations (3 yr): {rotation_years}')
    report_lines.append('-' * 25)

    if not_username is False:
        report_lines.append('CRITICAL — password must not match username.')
    else:
        report_lines.append('PASS Username and password do not match')

    if not_breached:
        report_lines.append('Breach check: PASS -- password not found in known breach list')
    else:
        report_lines.append('Breach check: CRITICAL -- password found in known breach list')

    report_lines.append(length_verdict)

    if has_digit:
        report_lines.append('NOTE: A digit was found in the password.')
    else:
        report_lines.append('NOTE: No digit was found in the password.')

    report_lines.append(f'Rotation Verdict: {rotation_verdict}')
    report_lines.append('-' * 25)

    if overall_pass:
        passed = 1
        failed = 0
        report_lines.append('OVERALL: PASS — password meets all checked criteria')
    else:
        passed = 0
        failed = 1
        report_lines.append('OVERALL: FAIL — see findings above')

    report_lines.append('=' * 25)
    return passed, failed, critical


if __name__ == '__main__':
    credentials = load_credentials("credentials.txt")
    known_breached = load_breached("breached.txt")
    report_lines = []

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
        report_lines.append('=' * 25)
        report_lines.append(f'Password Audit Report ( {batch_count}  of {batch_size} )')
        report_lines.append('=' * 25)

        passed, failed, critical = audit_password(
            cred["account"],
            cred["username"],
            cred["password"],
            cred["rotation_interval"],
            known_breached,
            policy,
            report_lines,
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

    report_lines.append('=' * 25)
    report_lines.append('Batch Summary')
    report_lines.append('=' * 25)
    report_lines.append(f'Total passwords audited: {summary.get("total", 0)}')
    report_lines.append(f'Total passed: {summary.get("passed", 0)}')
    report_lines.append(f'Total failed: {summary.get("failed", 0)}')
    report_lines.append(f'Failed accounts: {summary.get("failed_accounts", [])}')
    report_lines.append(f'CRITICAL accounts: {summary.get("critical", 0)}')
    report_lines.append(f'Critical accounts: {summary.get("critical_accounts", [])}')
    report_lines.append('=' * 25)

    for line in report_lines:
        print(line)
    write_report(report_lines, "report.txt")
