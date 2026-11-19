import json
import os
from datetime import datetime, timezone
from pathlib import Path


policy = {
    "min_length": 8,
    "strong_length": 15,
    "max_rotation_months": 12,
    "good_rotation_months": 6,
    "require_digit": True,
    "check_breach_list": True,
    "history_runs": 3,
}

AUDIT_LOG = "audit_log.jsonl"


def log_check(name, username, result, log_path):
    """Append one check result to the audit log as a JSON line."""
    # Combine the UTC timestamp, requested name, username, and result in one entry.
    entry = {
        # Dictionary keys label each value; isoformat() converts the UTC datetime to text.
        "time": datetime.now(timezone.utc).isoformat(),
        "check": name,
        "username": username,
        "result": result,
    }
    # Append rather than overwrite; the newline keeps entries separate.
    with open(log_path, "a", encoding="utf-8") as f:
        # with closes the file automatically; dumps() converts the dictionary to JSON text.
        f.write(json.dumps(entry) + "\n")


def read_audit_log(log_path):
    """Read audit log entries in file order, oldest first, skipping blank lines."""
    # Decode each nonblank JSON line without changing the order of the entries.
    entries = []
    # "r" opens for reading; iterating over f reads one line at a time.
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            # strip() removes surrounding whitespace, including the newline.
            line = line.strip()
            if line == "":
                # continue skips the remaining statements for this blank line.
                continue
            # loads() decodes JSON text; append() adds the dictionary to the list.
            entries.append(json.loads(line))
    # Return the accumulated list to the caller.
    return entries


def load_breached(filepath):
    """Read the breached password file. Returns a list of password strings."""
    # Strip line endings and collect only nonempty password lines.
    known_breached = []
    # The with block closes the file after the loop finishes.
    with open(filepath, "r") as f:
        for line in f:
            # != means "not equal"; empty lines are excluded from the list.
            line = line.strip()
            if line != "":
                known_breached.append(line)
    # Return all collected password strings after reading the whole file.
    return known_breached


def load_credentials(filepath):
    """Read the credentials file. Returns a list of credential dictionaries."""
    # Skip blank lines, then split each comma-separated record into named fields.
    credentials = []
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if line == "":
                # Move directly to the next line when there is no record to parse.
                continue

            # Convert the rotation field to an integer so checks can compare months.
            fields = line.split(",")
            # List indexes start at 0; each position supplies one dictionary value.
            credentials.append({
                "account": fields[0],
                "username": fields[1],
                "password": fields[2],
                "rotation_interval": int(fields[3]),
            })
    return credentials


def write_report(report_lines, filepath):
    """Write each string in report_lines to the file as one line."""
    # Replace the old report and add a newline after each supplied report line.
    with open(filepath, "w", encoding="utf-8") as f:
        # The for loop visits each string; + joins it to a newline before writing.
        for line in report_lines:
            f.write(line + "\n")


def save_summary(summary, filepath):
    """Write the summary dictionary to a JSON file."""
    # Replace the saved summary with indented JSON that is easy to read.
    with open(filepath, "w", encoding="utf-8") as f:
        # dump() writes Python data directly to the file; indent=2 formats nested data.
        json.dump(summary, f, indent=2)


def save_history(history, filepath):
    """Write the audit history list to a JSON file."""
    # Save the complete supplied history list, replacing the previous file.
    with open(filepath, "w", encoding="utf-8") as f:
        # JSON preserves the list order and the dictionaries stored inside it.
        json.dump(history, f, indent=2)


def load_summary(filepath):
    """Read and return the summary dictionary from a JSON file."""
    # Decode the saved JSON back into Python data.
    with open(filepath, "r", encoding="utf-8") as f:
        # load() reads JSON from the file; return sends the decoded dictionary back.
        return json.load(f)


def load_history(filepath):
    """Return saved audit history, or an empty list when it does not exist."""
    # A first run has no history file, so start with an empty list.
    if not os.path.exists(filepath):
        # not reverses the existence check; return exits the function immediately.
        return []

    with open(filepath, "r", encoding="utf-8") as f:
        # If the file exists, load its JSON data as the saved history list.
        return json.load(f)


def add_to_history(history, summary, keep):
    """Add one audit summary and return the newest requested history entries."""
    # Continue numbering from the last saved run, or start at 1 for new history.
    if history:
        # A nonempty list is truthy; [-1] selects its last dictionary.
        run_number = history[-1]["run"] + 1
    else:
        # An empty list is falsey, so its first run gets number 1.
        run_number = 1

    # Store summary counts only, then keep the final requested number of runs.
    history.append({
        "run": run_number,
        "total": summary["total"],
        "failed": summary["failed"],
        "critical": summary["critical"],
    })
    # A negative slice starts keep items from the end and includes everything after it.
    return history[-keep:]


def check_length(password, policy):
    """Return whether *password* meets the policy length requirement and its verdict."""
    # Use the midpoint between minimum and strong lengths for the moderate rating.
    password_length = len(password)
    # Parentheses group the two policy values into a tuple.
    length_thresholds = (
        policy["min_length"],
        policy["strong_length"],
    )
    # sum() adds the values; len() counts them; // divides and rounds down here.
    moderate_limit = sum(length_thresholds) // len(length_thresholds)

    # Select a descriptive rating based on the password's character count.
    # if/elif/else uses the first matching branch and skips the remaining branches.
    if password_length < policy["min_length"]:
        length_verdict = 'WEAK — does not meet minimum length requirements'
    elif password_length <= moderate_limit:
        length_verdict = 'MODERATE — meets minimum but falls short of NIST recommendations'
    elif password_length < policy["strong_length"]:
        length_verdict = 'GOOD — acceptable length for most systems'
    else:
        length_verdict = 'STRONG — meets NIST SP 800-63B recommendations'

    # Passing this check requires the strong-length threshold.
    length_ok = password_length >= policy["strong_length"]
    # A comma returns two values as a tuple: the boolean and the description.
    return length_ok, length_verdict


def check_digit(password):
    """Return True when *password* contains at least one ASCII digit."""
    # Scan every character; finding any digit makes the final result True.
    has_digit = False
    # Iterating over a string gives one character at a time.
    for char in password:
        # in tests whether this character belongs to the string of allowed digits.
        if char in '0123456789':
            has_digit = True

    return has_digit


def check_username(password, username):
    """Return True when the password is different from the username."""
    # Compare the complete strings exactly, including uppercase and lowercase.
    # != produces a boolean: True for different strings and False for equal strings.
    not_username = password != username
    return not_username


def check_rotation(rotation_interval, policy):
    """Return whether the rotation interval is acceptable and its verdict."""
    # Intervals at or below the maximum pass; shorter intervals get better ratings.
    rotation_ok = rotation_interval <= policy["max_rotation_months"]

    # > and >= compare month counts; square brackets retrieve policy values by key.
    if rotation_interval > policy["max_rotation_months"]:
        rotation_verdict = (
            'WARNING — rotation interval exceeds recommended maximum of '
            f'{policy["max_rotation_months"]} months'
        )
    elif rotation_interval >= policy["good_rotation_months"]:
        rotation_verdict = 'ACCEPTABLE — rotation interval within recommended range'
    else:
        rotation_verdict = 'EXCELLENT — frequent rotation policy detected'

    # Return both values so a caller can unpack them into two variables.
    return rotation_ok, rotation_verdict


def check_breach(password, known_breached):
    """Return True when *password* is not in the known breached-password list."""
    # Membership means the password is known to be breached, so it fails the check.
    # not in returns True only when no list item equals the supplied password.
    not_breached = password not in known_breached
    return not_breached


def breach_verdicts(username, credentials, known_breached):
    """Return breach-list verdicts for every credential belonging to *username*."""
    # Filter by username and report breach status without returning passwords.
    # Invert check_breach because on_breach_list means the password failed.
    accounts = []
    # Each loop iteration reads one credential dictionary from the list.
    for credential in credentials:
        # == compares the stored username with the requested username.
        if credential["username"] == username:
            accounts.append({
                "account": credential["account"],
                # not reverses the helper's safe/unsafe boolean.
                "on_breach_list": not check_breach(
                    credential["password"], known_breached
                ),
            })

    # The returned dictionary pairs the requested user with the collected account list.
    return {"username": username, "accounts": accounts}


def length_verdicts(username, credentials, known_breached):
    """Return password-length verdicts for every credential belonging to *username*."""
    # Check matching accounts and keep only the pass/fail value, not the verdict text.
    accounts = []
    for credential in credentials:
        if credential["username"] == username:
            # Unpack the two returned values; _ holds the description we do not use.
            long_enough, _ = check_length(credential["password"], policy)
            # append() adds one account dictionary to the end of the list.
            accounts.append({
                "account": credential["account"],
                "long_enough": long_enough,
            })

    return {"username": username, "accounts": accounts}


def rotation_verdicts(username, credentials, known_breached):
    """Return rotation verdicts for every credential belonging to *username*."""
    # For matching accounts, report the interval and whether it passes the policy.
    accounts = []
    for credential in credentials:
        if credential["username"] == username:
            # Read this dictionary field and pass it to the rotation-check function.
            rotation_interval = credential["rotation_interval"]
            # Unpack the boolean and discard the description by assigning it to _.
            rotation_ok, _ = check_rotation(rotation_interval, policy)
            # Keep the original month count together with the check's boolean result.
            accounts.append({
                "account": credential["account"],
                "rotation_months": rotation_interval,
                "rotation_ok": rotation_ok,
            })

    return {"username": username, "accounts": accounts}


CHECKS = {
    "check_breach": breach_verdicts,
    "check_length": length_verdicts,
    "check_rotation": rotation_verdicts,
}
CHECK_NAMES = list(CHECKS)


def run_check(check_name, username, credentials, known_breached):
    """Run the verdict helper associated with *check_name* for *username*."""
    # Look up approved names in CHECKS; all other names receive an error result.
    if check_name in CHECKS:
        # Dictionary lookup retrieves a function; (...) calls it with these arguments.
        result = CHECKS[check_name](username, credentials, known_breached)
    else:
        # Store an error dictionary so both branches can use the same logging code.
        result = {"error": "unknown check"}

    # Record both accepted and refused checks before returning their results.
    log_check(check_name, username, result, AUDIT_LOG)
    return result


def audit_password(account, username, password, rotation_interval, known_breached, policy, report_lines):
    """Append one password audit to report_lines and return its pass, fail, and critical deltas."""
    # Run the individual checks and collect their boolean results and descriptions.
    # Assignments with two names unpack the tuple returned by the helper.
    length_ok, length_verdict = check_length(password, policy)
    has_digit = check_digit(password)
    not_username = check_username(password, username)
    rotation_ok, rotation_verdict = check_rotation(rotation_interval, policy)
    not_breached = check_breach(password, known_breached)

    # Calculate the numeric values displayed in this account's report.
    password_length = len(password)
    # len() counts characters, * multiplies, and // performs integer division.
    length_score = password_length * 10
    rotation_count = 36 // rotation_interval
    rotation_years = 3 // rotation_interval

    # Overall success uses these four checks; rotation is reported separately.
    # Matching the username or appearing on the breach list is a critical finding.
    # and requires every boolean to be True; or requires at least one to be True.
    overall_pass = length_ok and has_digit and not_username and not_breached
    # This conditional expression selects 1 for a critical finding, otherwise 0.
    critical = 1 if not_username is False or not_breached is False else 0

    report_lines.append('=' * 25)
    # Add account details and readable findings to the shared report list.
    # append() changes the caller's list; + joins strings and f-strings insert values.
    report_lines.append('Account:' + account)
    report_lines.append('Username:' + username)
    report_lines.append(f'Password Length: {password_length} characters')
    report_lines.append(f'Length Score: {length_score} points')
    report_lines.append(f'Rotation Interval: {rotation_count} months')
    report_lines.append(f'Rotations (3 yr): {rotation_years}')
    report_lines.append('-' * 25)

    if not_username is False:
        # is False tests the boolean result; else handles a passing username check.
        report_lines.append('CRITICAL — password must not match username.')
    else:
        report_lines.append('PASS Username and password do not match')

    if not_breached:
        # A True boolean enters this branch; False enters the else branch.
        report_lines.append('Breach check: PASS -- password not found in known breach list')
    else:
        report_lines.append('Breach check: CRITICAL -- password found in known breach list')

    report_lines.append(length_verdict)

    if has_digit:
        # Choose the report message according to the digit check's boolean.
        report_lines.append('NOTE: A digit was found in the password.')
    else:
        report_lines.append('NOTE: No digit was found in the password.')

    report_lines.append(f'Rotation Verdict: {rotation_verdict}')
    report_lines.append('-' * 25)

    # Return counts of 0 or 1 so the caller can add them to the batch totals.
    if overall_pass:
        passed = 1
        failed = 0
        report_lines.append('OVERALL: PASS — password meets all checked criteria')
    else:
        passed = 0
        failed = 1
        report_lines.append('OVERALL: FAIL — see findings above')

    report_lines.append('=' * 25)
    # Return a tuple of three counts for the caller to unpack and add to its totals.
    return passed, failed, critical


if __name__ == '__main__':
    base_dir = Path(__file__).resolve().parent
    credentials = load_credentials(base_dir / "credentials.txt")
    known_breached = load_breached(base_dir / "breached.txt")
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
    save_summary(summary, "summary.json")

    history = load_history("audit_history.json")
    history = add_to_history(history, summary, policy["history_runs"])
    save_history(history, "audit_history.json")

    verdicts = breach_verdicts("jsmith", credentials, known_breached)
    print(json.dumps(verdicts, indent=2))
    with open("breach_check.json", "w", encoding="utf-8") as f:
        json.dump(verdicts, f, indent=2)

    all_checks = {}
    for check_name in CHECK_NAMES:
        all_checks[check_name] = run_check(
            check_name, "jsmith", credentials, known_breached
        )
    with open("all_checks.json", "w", encoding="utf-8") as f:
        json.dump(all_checks, f, indent=2)

    print(f'Audit log entries: {len(read_audit_log(AUDIT_LOG))}')
