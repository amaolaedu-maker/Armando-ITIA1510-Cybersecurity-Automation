number = int(input("input number please and thank you:"))

if number % 3 == 0 and number % 5 == 0:
    print('fizz buzz')

elif number % 3 == 0:
    print('fizz')

elif number % 5 == 0:
    print('buzz')

else: 
    print('No fizz nor buzz')
