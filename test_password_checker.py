"""Direct assertion tests for the password-checker functions."""

import json
from pathlib import Path

from password_checker import (
    check_length,
    check_digit,
    check_username,
    check_rotation,
    check_breach,
    breach_verdicts,
    length_verdicts,
    rotation_verdicts,
    run_check,
    load_credentials,
    load_breached,
    write_report,
    save_summary,
    load_summary,
    load_history,
    add_to_history,
    save_history,
    policy,
)


TEST_DIR = Path(__file__).resolve().parent
known_breached = load_breached(TEST_DIR / "breached.txt")


def print_test_summary(all_tests_passed):
    """Prints the test summary. Takes all_tests_passed: bool. Returns None."""
    if all_tests_passed:
        print('-' * 50)
        print('All 29 tests passed')
    else:
        print('-' * 50)
        print('FAIL: One or more tests failed.')


def run_tests():
    """Runs twenty-nine password-checker assertions. Takes no parameters. Returns None."""
    try:
        # Each assertion checks one expected result before its PASS message is printed.
        # policy: expected value and required setting
        assert policy["strong_length"] == 15
        print('PASS: policy includes the expected strong-length requirement')

        assert "require_digit" in policy
        print('PASS: policy includes the require_digit setting')

        # check_length: weak password and strong password
        length_ok, length_verdict = check_length('pass', policy)
        assert length_ok == False
        print('PASS: check_length correctly identified weak password')

        length_ok, length_verdict = check_length('a' * 16, policy)
        assert length_ok == True
        print('PASS: check_length correctly identified strong password')

        # check_digit: no digit and at least one digit
        has_digit = check_digit('Password')
        assert has_digit == False
        print('PASS: check_digit correctly identified a password with no digits')

        has_digit = check_digit('Password1')
        assert has_digit == True
        print('PASS: check_digit correctly identified a password with a digit')

        # check_username: matching and non-matching values
        not_username = check_username('student', 'student')
        assert not_username == False
        print('PASS: check_username correctly identified matching username and password')

        not_username = check_username('SafePassword1', 'student')
        assert not_username == True
        print('PASS: check_username correctly identified different username and password')

        # check_rotation: unacceptable and acceptable intervals
        rotation_ok, rotation_verdict = check_rotation(18, policy)
        assert rotation_ok == False
        print('PASS: check_rotation correctly identified an unacceptable interval')

        rotation_ok, rotation_verdict = check_rotation(6, policy)
        assert rotation_ok == True
        print('PASS: check_rotation correctly identified an acceptable interval')

        # load_credentials: list result and expected dictionary keys
        credentials = load_credentials(TEST_DIR / 'credentials.txt')
        assert isinstance(credentials, list)
        print('PASS: load_credentials returned a list')

        assert 'account' in credentials[0]
        print('PASS: load_credentials returned credential dictionaries with account keys')

        # load_breached: list result and known password
        breached_passwords = load_breached(TEST_DIR / 'breached.txt')
        assert isinstance(breached_passwords, list)
        print('PASS: load_breached returned a list')

        assert 'password123' in breached_passwords
        print('PASS: load_breached included password123')

        # breach_verdicts: known breached account, unknown username, and no passwords exposed
        result = breach_verdicts("jsmith", credentials, known_breached)
        assert result["accounts"][0] == {"account": "Gmail", "on_breach_list": True}
        print('PASS: breach_verdicts marked the Gmail password as on the breach list')

        result = breach_verdicts("nobody", credentials, known_breached)
        assert result["accounts"] == []
        print('PASS: breach_verdicts returned no accounts for nobody')

        result = breach_verdicts("jsmith", credentials, known_breached)
        result_text = json.dumps(result)
        credential_passwords = [
            credential["password"]
            for credential in credentials
            if credential["account"] != "SSH Server"
        ]
        assert all(password not in result_text for password in credential_passwords)
        print('PASS: breach_verdicts result contains no credential passwords')

        # New verdict helpers and dispatcher: expected results and unknown check rejection
        result = length_verdicts("jsmith", credentials, known_breached)
        assert result["accounts"][2] == {"account": "VPN", "long_enough": True}
        print('PASS: length_verdicts marked the third jsmith account as long enough')

        result = rotation_verdicts("jsmith", credentials, known_breached)
        assert result["accounts"][1] == {
            "account": "SSH Server",
            "rotation_months": 24,
            "rotation_ok": False,
        }
        print('PASS: rotation_verdicts reported the SSH Server rotation failure')

        assert run_check("check_breach", "jsmith", credentials, known_breached) == (
            breach_verdicts("jsmith", credentials, known_breached)
        )
        print('PASS: run_check dispatched check_breach to breach_verdicts')

        assert run_check(
            "reset_password", "jsmith", credentials, known_breached
        ) == {"error": "unknown check"}
        print('PASS: run_check refused a name that is not one of its checks')

        # write_report: verify that every supplied line is written to the file
        test_lines = ['first test line', 'second test line']
        write_report(test_lines, TEST_DIR / 'test_report.txt')
        with open(TEST_DIR / 'test_report.txt', 'r') as f:
            report_text = f.read()
        assert report_text == 'first test line\nsecond test line\n'
        print('PASS: write_report wrote the expected report text')

        # save_summary/load_summary: preserve data and avoid writing passwords to JSON
        sample = {
            'total': 2,
            'passed': 1,
            'failed': 1,
            'critical': 1,
            'failed_accounts': ['Gmail'],
            'critical_accounts': ['Gmail'],
        }
        save_summary(sample, TEST_DIR / 'test_summary.json')
        loaded_summary = load_summary(TEST_DIR / 'test_summary.json')

        assert loaded_summary == sample
        print('PASS: save_summary and load_summary gave back the same dictionary')

        assert isinstance(loaded_summary['failed_accounts'], list)
        print('PASS: loaded failed_accounts is a list')

        with open(TEST_DIR / 'test_summary.json', 'r', encoding='utf-8') as f:
            saved_summary_text = f.read()
        assert all(credential['password'] not in saved_summary_text for credential in credentials)
        print('PASS: saved summary does not contain credential passwords')

        # history: first-run loading, numbering, trimming, and JSON round trip
        assert load_history(TEST_DIR / 'test_missing_history.json') == []
        print('PASS: load_history returned an empty list for a missing file')

        history = add_to_history([], sample, 2)
        assert len(history) == 1 and history[0]['run'] == 1
        print('PASS: add_to_history started an empty history at run 1')

        history = []
        for i in range(3):
            history = add_to_history(history, sample, 2)
        assert [entry['run'] for entry in history] == [2, 3]
        print('PASS: add_to_history kept only the newest 2 runs')

        history_file = TEST_DIR / 'test_audit_history.json'
        save_history(history, history_file)
        assert load_history(history_file) == history
        print('PASS: save_history and load_history gave back the same history')
    except AssertionError:
        # Show a summary before raising the error so a failed test is obvious.
        print_test_summary(False)
        raise
    else:
        print_test_summary(True)


# Run the tests only when this file is executed directly, not when it is imported.
if __name__ == '__main__':
    run_tests()
