print('Password Audit Report')

# Collects the information for much much later use and present use
account = input('What is your Gmail?')
username = input('What is your Username?')
password = input('What is your Password?')

#  The rotation interval is set for 3 years
#  and the function below will convert it
#  into an interger for the rotation count
#  to determine the rotation and interval.

rotation_interval_string = input('What is your Rotation Interval?')
rotation_interval = int(rotation_interval_string)


# This is to do two things one creates
# the rotation count for months
#  Two divides the rotation interval into proper years
rotation_count = 36 / rotation_interval
rotation_years = 365 / rotation_interval

#  Longer passwords earn a higher reward
#  Alongside collecting the password length
password_length = len(password)
length_score = password_length * 10


print('Account:' + account)
print('Username:' + username)
print('Password Length:', password_length, 'characters')
print('Length Score:', length_score, 'points')
print('Rotation Interval:', rotation_count, 'months')
print('Rotations (3 yr):', rotation_years)
