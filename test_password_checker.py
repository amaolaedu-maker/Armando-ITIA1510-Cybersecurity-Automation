"""Direct assertion tests for the password-checker functions."""

from password_checker import (
    check_length,
    check_digit,
    check_username,
    check_rotation,
    check_breach,
    load_credentials,
    load_breached,
    write_report,
    policy,
)


known_breached = load_breached("breached.txt")


def print_test_summary(all_tests_passed):
    """Prints the test summary. Takes all_tests_passed: bool. Returns None."""
    if all_tests_passed:
        print('-' * 50)
        print('All 15 tests passed')
    else:
        print('-' * 50)
        print('FAIL: One or more tests failed.')


def run_tests():
    """Runs fifteen password-checker assertions. Takes no parameters. Returns None."""
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
        credentials = load_credentials('credentials.txt')
        assert isinstance(credentials, list)
        print('PASS: load_credentials returned a list')

        assert 'account' in credentials[0]
        print('PASS: load_credentials returned credential dictionaries with account keys')

        # load_breached: list result and known password
        breached_passwords = load_breached('breached.txt')
        assert isinstance(breached_passwords, list)
        print('PASS: load_breached returned a list')

        assert 'password123' in breached_passwords
        print('PASS: load_breached included password123')

        # write_report: verify that every supplied line is written to the file
        test_lines = ['first test line', 'second test line']
        write_report(test_lines, 'test_report.txt')
        with open('test_report.txt', 'r') as f:
            report_text = f.read()
        assert report_text == 'first test line\nsecond test line\n'
        print('PASS: write_report wrote the expected report text')
    except AssertionError:
        # Show a summary before raising the error so a failed test is obvious.
        print_test_summary(False)
        raise
    else:
        print_test_summary(True)


# Run the tests only when this file is executed directly, not when it is imported.
if __name__ == '__main__':
    run_tests()
