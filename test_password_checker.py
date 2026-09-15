"""Direct assertion tests for the password-checker functions."""

from password_checker import check_length, check_digit, check_username, check_rotation


def print_test_summary(all_tests_passed):
    """Prints the test summary. Takes all_tests_passed: bool. Returns None."""
    if all_tests_passed:
        print('-' * 50)
        print('All 8 tests passed')
    else:
        print('-' * 50)
        print('FAIL: One or more tests failed.')


def run_tests():
    """Runs eight password-checker assertions. Takes no parameters. Returns None."""
    try:
        # Each assertion checks one expected result before its PASS message is printed.
        # check_length: weak password and strong password
        length_ok, length_verdict = check_length('pass')
        assert length_ok == False
        print('PASS: check_length correctly identified weak password')

        length_ok, length_verdict = check_length('a' * 16)
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
        rotation_ok, rotation_verdict = check_rotation(18)
        assert rotation_ok == False
        print('PASS: check_rotation correctly identified an unacceptable interval')

        rotation_ok, rotation_verdict = check_rotation(6)
        assert rotation_ok == True
        print('PASS: check_rotation correctly identified an acceptable interval')
    except AssertionError:
        # Show a summary before raising the error so a failed test is obvious.
        print_test_summary(False)
        raise
    else:
        print_test_summary(True)


# Run the tests only when this file is executed directly, not when it is imported.
if __name__ == '__main__':
    run_tests()
