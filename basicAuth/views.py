from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from buas import settings
from django.core.mail import EmailMessage, send_mail

subject = 'Test Email'
message = 'This is a test email.'
from_email = 'your-email@example.com'
recipient_list = ['recipient1@example.com', 'recipient2@example.com']

send_mail(subject, message, from_email, recipient_list)

# Create your views here.
def home(request):
    context = {}
    if request.user.is_authenticated:
        context['fname'] = request.user.first_name
    return render(request, 'basicAuth/index.html', context)

def signup(request):

    if request.method == 'POST':

        # Get the post parameters
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        pass1 = request.POST['pass1']
        pass2 = request.POST['pass2']

        # Debug statements to print the values of each field
        print("Username:", username)
        print("First Name:", fname)
        print("Last Name:", lname)
        print("Email:", email)
        print("Password 1:", pass1)
        print("Password 2:", pass2)

        # Check for errorneous input
        if User.objects.filter(username=username):
            print("Username already exist! Please try some other username.")
            messages.error(request, "Username already exist! Please try some other username.")
            return redirect('signup')
        
        if User.objects.filter(email=email).exists():
            print("Email Already Registered!!")
            messages.error(request, "Email Already Registered!!")
            return redirect('signup')
        
        if len(username)>20:
            print("Username must be under 20 charcters!!")
            messages.error(request, "Username must be under 20 charcters!!")
            return redirect('signup')
        
        if len(username) < 4:
            print("Username must be at least 4 characters long!!")
            messages.error(request, "Username must be at least 4 characters long!!")
            return redirect('signup')
        
        if len(pass1)<4:
            print("Password must be at least 8 characters long!!")
            messages.error(request, "Password must be at least 8 characters long!!")
            return redirect('signup')
        
        if pass1 != pass2:
            print("Passwords didn't matched!!")
            messages.error(request, "Passwords didn't matched!!")
            return redirect('signup')
        
        if not username.isalnum(): 
            print("Username must be Alpha-Numeric!!")
            messages.error(request, "Username must be Alpha-Numeric!!")
            return redirect('signup')

        # Create the user
        myuser = User.objects.create_user(username, email, pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False
        myuser.save()
        messages.success(request, "Your account has been successfully created")

        #welcome email

        return redirect('home')

    return render(request, 'basicAuth/signup.html')

def signin(request):

    if request.method == 'POST':

        email = request.POST['email']
        password = request.POST['password']
        user = authenticate(request, email=email, password=password)

        if user is not None:

            login(request, user)
            messages.success(request, "Successfully Logged In")
            return redirect('home')
        
        else:

            messages.error(request, "Invalid Credentials, Please try again")
            return redirect('home')

    return render (request, 'basicAuth/signin.html')

def signout(request):
    
    logout(request)
    messages.success(request, "Successfully Logged Out")
    return redirect('home')
    