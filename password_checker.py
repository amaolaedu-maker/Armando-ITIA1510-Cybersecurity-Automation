

# Collects the information for much much later use and present use
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

    
   

# This new variable will be checking 
# if the username is the same as the password
#  this will be important for a variable later
    not_username = password != username


#  The rotation interval is set for 3 years
#  and the function below will convert it
#  into an interger for the rotation count
#  to determine the rotation and interval.

    rotation_interval = int(rotation_interval_string)


# This is to do two things one creates
# the rotation count for months
#  Two divides the rotation interval into proper years
    rotation_count = 36 / rotation_interval 
    rotation_years = 3 / rotation_interval 


    if rotation_interval > 12:
        rotation_verdict = 'WARNING — rotation interval exceeds recommended maximum of 12 months'
    elif rotation_interval >= 6 and rotation_interval <= 12:
        rotation_verdict = 'ACCEPTABLE — rotation interval within recommended range'
    else:
        rotation_verdict = 'EXCELLENT — frequent rotation policy detected'


#  Longer passwords earn a higher reward
#  Alongside collecting the password length
    password_length = len(password)
    length_score = password_length * 10

# Classify the password length using the required length ranges.
    if password_length < 8:
        length_verdict = 'WEAK — does not meet minimum length requirements'
    elif password_length <= 11:
        length_verdict = 'MODERATE — meets minimum but falls short of NIST recommendations'
    elif password_length <= 14:
        length_verdict = 'GOOD — acceptable length for most systems'
    else:
        length_verdict = 'STRONG — meets NIST SP 800-63B recommendations'

# now we will be adding a variable to store 
# and check the password length 
    length_ok = password_length >= 15


# this is a the has digit, It is a variable 
# that will store and check if the password variable
# has a number inside of it
    has_digit = False
    for char in password:
        if char in '0123456789':
            has_digit = True

# this is combining every boolean check we have made
# so far into a singular verdict 
    overall_pass = length_ok and has_digit and not_username

    print('=' * 25)
    print('Account:' + account)
    print('Username:' + username)
    print('Password Length:', password_length, 'characters')
    print('Length Score:', length_score, 'points')
    print('Rotation Interval:', rotation_count, 'months')
    print('Rotations (3 yr):', rotation_years)
    print('-' * 25)

# This is a false statement meant if the
    # Password and user name match
    if not_username is False:
        critical_count += 1
        print('CRITICAL — password must not match username.')
    else: 
        print('PASS Username and password do not match')

    print(length_verdict)

    # We are checking down here to see 
    # if the has digit activates or not
    if has_digit:
        print('NOTE: A digit was found in the password.')
    elif not has_digit:
        print('NOTE: No digit was found in the password.')

    print('Rotation Verdict:', rotation_verdict)

    print('-' * 25)

    # We are checking down here if the overpass meets all of the
    # requirements and prints out a statement depending on if its true or notw
    if overall_pass is True:
        total_pass += 1
        print('OVERALL: PASS — password meets all checked criteria')
    else:
        total_fail += 1
        print('OVERALL: FAIL — see findings above')


    print('=' * 25)
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
