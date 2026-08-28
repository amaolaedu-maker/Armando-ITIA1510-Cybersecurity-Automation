number = int(input())

if number % 5 == 3:
    print('fizz buzz')

elif number % 3 == 0:
    print('fizz')

elif number % 5 == 0:
    print('buzz')

else: 
    print('No fizz nor buzz')

