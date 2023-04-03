from django.shortcuts import render, redirect
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_str
from django.core.mail import send_mail
from django.contrib.auth.models import User
from django.contrib import messages
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.hashers import check_password
from django import forms
from .models import UserProfile
import re

def hex_to_rgb(hex):

    hex = hex.lstrip('#')

    return tuple(int(hex[i:i+2], 16) for i in (0, 2, 4))

def home(request):

    user = request.user
    primary_color = None
    secondary_color = None
    fname = None
    lname = None
    username = None

    if request.user.is_authenticated:

        fname = request.user.first_name
        lname = request.user.last_name
        username = request.user.username

        user_profile = UserProfile.objects.get_or_create(user=user, defaults={'primary_color': '#6D6D6D', 'secondary_color': '#FFFFFF'})[0]

        primary_color = user_profile.primary_color
        secondary_color = user_profile.secondary_color

    context = {

        'fname': fname,
        'lname': lname,
        'username': username,
        'primary_color': primary_color,
        'secondary_color': secondary_color
    }

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
        primary_color = request.POST['primary_color']
        secondary_color = request.POST['secondary_color']

        # Check for errorneous input
        if User.objects.filter(username=username):

            messages.error(request, "Username already exists! Please try some other username.")
            return redirect('signup')
        
        if User.objects.filter(email=email).exists():

            messages.error(request, "Email already registered!!")
            return redirect('signup')
        
        if len(username)>20:

            messages.error(request, "Username must be under 20 charcters!!")
            return redirect('signup')
        
        if len(username) < 4:

            messages.error(request, "Username must be at least 4 characters!!")
            return redirect('signup')
        
        if len(pass1)<5:

            messages.error(request, "Password must be at least 5 characters!!")
            return redirect('signup')
        
        if pass1 != pass2:

            messages.error(request, "Passwords didn't match!!")
            return redirect('signup')
        
        if not re.match("^[A-Za-z0-9_.]*$", username):

            messages.error(request, "Username must be alphanumeric and may include underscores!")
            return redirect('signup')

        # Create the user
        myuser = User.objects.create_user(username, email, pass1)
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.is_active = False
        myuser.save()

        profile, created = UserProfile.objects.update_or_create(
            user=myuser,
            defaults={'primary_color': primary_color, 
                      'secondary_color': secondary_color}
        )

        # Send activation email
        send_activation_email(request, myuser)

        messages.success(request, "Your account has been successfully created! Please check your email for activation link.")
        
        return redirect('home')

    return render(request, 'basicAuth/signup.html')

def signin(request):

    if request.method == 'POST':

        identifier = request.POST['identifier']
        password = request.POST['password']

        user = authenticate(request, username=identifier, password=password)

        if user is not None:

            if user.is_active:

                login(request, user)
                messages.success(request, "Successfully Logged In")
                return redirect('home')
            
            else:

                messages.error(request, "Your account is not activated yet! Please check your email for activation link.")
                resend_activation_email(request, user)
                return redirect('signin')
            
        else:

            messages.error(request, "Invalid Credentials, Please try again")
            return redirect('signin')

    return render(request, 'basicAuth/signin.html')

@login_required
def signout(request):
    
    logout(request)
    messages.success(request, "Successfully Logged Out")
    return redirect('home')

@login_required  
def profile(request):

    if request.user.is_authenticated:

        user = request.user
        user_profile = UserProfile.objects.get_or_create(user=user, defaults={'primary_color': '#6D6D6D'})[0]
        primary_color = user_profile.primary_color
        secondary_color = user_profile.secondary_color

        context = {

            'primary_color': primary_color,
            'secondary_color': secondary_color
        }

        return render(request, 'basicAuth/profile.html', context)

    else:

        return redirect('home')

@login_required
def update(request):

    if request.method == 'POST':

        # Get the post parameters
        username = request.POST['username']
        fname = request.POST['fname']
        lname = request.POST['lname']
        email = request.POST['email']
        primary_color = request.POST['primary_color']
        secondary_color = request.POST['secondary_color']

        # Check for erroneous input
        if len(username) > 20:

            messages.error(request, "Username must be under 20 characters!")
            return redirect('profile')

        if len(username) < 4:

            messages.error(request, "Username must be at least 4 characters long!")
            return redirect('profile')

        if not re.match("^[A-Za-z0-9_.]*$", username):
            
            messages.error(request, "Username must be alphanumeric and may include underscores!")
            return redirect('signup')
        
        user_pk = request.user.pk

        if User.objects.exclude(pk=user_pk).filter(username=username):

            messages.error(request, "Username already exists! Please try some other username.")
            return redirect('signup')

        if User.objects.exclude(pk=user_pk).filter(email=email).exists():

            messages.error(request, "Email already registered!!")
            return redirect('signup')

        # Update the user information
        myuser = request.user
        myuser.username = username
        myuser.email = email
        myuser.first_name = fname
        myuser.last_name = lname
        myuser.save()

        setPrimaryColor(request, primary_color)
        setSecondaryColor(request, secondary_color)

        messages.success(request, "Your account has been successfully updated")

        return redirect('profile')

    return render(request, 'basicAuth/profile.html')

@login_required
def changePassword(request):

    if request.user.is_authenticated:

        user_profile = UserProfile.objects.get_or_create(user=request.user, defaults={'primary_color': '#6D6D6D'})[0]
        primary_color = user_profile.primary_color
        secondary_color = user_profile.secondary_color
        secondary_color_rgb = hex_to_rgb(secondary_color)

        if request.method == 'POST':

            # Get the post parameters
            oldpass = request.POST['oldpass']
            newpass1 = request.POST['newpass1']
            newpass2 = request.POST['newpass2']

            # Check for erroneous input
            if newpass1 != newpass2:
                messages.error(request, "Passwords didn't match!")
                return redirect('changePassword')

            if len(newpass1) < 4: 
                messages.error(request, "Password must be at least 8 characters long!")
                return redirect('changePassword')

            myuser = request.user

            # Check if the old password is correct
            if not check_password(oldpass, myuser.password):
                messages.error(request, "The old password is incorrect!")
                return redirect('changePassword')

            # Update the user's password
            myuser.set_password(newpass1)
            myuser.save()
            
            # Update the session hash to keep the user logged in after the password change
            update_session_auth_hash(request, myuser)

            messages.success(request, "Your password has been successfully updated")
            return redirect('profile')
        
    context = {

            'primary_color': primary_color,
            'secondary_color': secondary_color,
            'secondary_color_rgb': secondary_color_rgb,
        }

    return render(request, 'basicAuth/changePassword.html', context)

@login_required
def delete(request):

    if request.user.is_authenticated:

        user_profile = UserProfile.objects.get_or_create(user=request.user, defaults={'primary_color': '#6D6D6D'})[0]
        primary_color = user_profile.primary_color
        secondary_color = user_profile.secondary_color
        secondary_color_rgb = hex_to_rgb(secondary_color)

        if request.method == 'POST':

            password = request.POST['pass']

            myuser = request.user
            if not check_password(password, myuser.password):
                messages.error(request, "The password is incorrect!")
                return redirect('delete')

            myuser.delete()
            messages.success(request, "Your account has been successfully deleted")
            return redirect('home')
        
    context = {

            'primary_color': primary_color,
            'secondary_color': secondary_color,
            'secondary_color_rgb': secondary_color_rgb,
    }
    
    return render(request, 'basicAuth/delete.html', context)

def activate(request, uidb64, token):

    try:

        uid = force_str(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)

    except (TypeError, ValueError, OverflowError, User.DoesNotExist):

        user = None

    if user is not None and default_token_generator.check_token(user, token):

        user.is_active = True
        user.save()
        messages.success(request, 'Your account has been activated. You can now log in.')
        return redirect('signin')  # Replace 'login' with the name of your login view
    
    else:

        messages.error(request, 'Activation link is invalid or has expired.')
        return redirect('home')  # Replace 'home' with the name of your homepage view
    
def send_activation_email(request, user):

    user = User.objects.select_related('userprofile').get(pk=user.pk)

    token = default_token_generator.make_token(user)

    uidb64 = urlsafe_base64_encode(force_bytes(user.pk))

    activation_link = request.build_absolute_uri(reverse('activate', args=[uidb64, token]))

    subject = 'Activate your account'
    message = f'''Account Created Successfully!

                First Name: {user.first_name}
                Last Name: {user.last_name}
                Username: {user.username}
                Email: {user.email}

                Color: {user.userprofile.primary_color}

                Click the link below to activate your account:

                {activation_link}'''
    
    from_email = 'rotatingcloudbasicauth@gmail.com' 
    recipient_list = [user.email]

    send_mail(subject, message, from_email, recipient_list)

@login_required
def resend_activation_email(request):

    user = request.user

    if not user.is_active:

        send_activation_email(request, user)
        messages.success(request, 'An activation email has been sent to your email address.')
        return redirect('signin')
    
    else:

        messages.error(request, 'Your account is already active.')

    return redirect('profile')

@login_required
def setPrimaryColor(request, color):
    
    if request.user.is_authenticated:

        user = request.user
        userprofile = UserProfile.objects.get(user=user)
        userprofile.primary_color = color
        userprofile.save()

    else:

        messages.error(request, "There was error setting your color. Please try again.")

@login_required
def setSecondaryColor(request, color):
        
        if request.user.is_authenticated:
    
            user = request.user
            userprofile = UserProfile.objects.get(user=user)
            userprofile.secondary_color = color
            userprofile.save()
    
        else:
    
            messages.error(request, "There was error setting your color. Please try again.")

class UserProfileForm(forms.ModelForm):

    class Meta:

        model = UserProfile
        fields = ('primary_color', 'secondary_color')