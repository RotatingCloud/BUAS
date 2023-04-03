from django.contrib import admin
from django.urls import path, include
from . import views

urlpatterns = [
    
    path('', views.home, name='home'),
    path('signup', views.signup, name='signup'),
    path('signin', views.signin, name='signin'),
    path('signout', views.signout, name='signout'),
    path('profile/', views.profile, name='profile'),
    path('update', views.update, name='update'),
    path('changepassword/', views.changepassword, name='changepassword'),
    path('delete/', views.delete, name='delete'),
    path('activate/<uidb64>/<token>', views.activate, name='activate'),
    path('resend_activation_email/', views.resend_activation_email, name='resend_activation_email'),
    path('setBackgroundColor', views.setBackgroundColor, name='setBackgroundColor'),
    path('setTextColor', views.setTextColor, name='setTextColor'),
]
