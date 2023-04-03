from django.contrib.auth.backends import BaseBackend
from django.contrib.auth.models import User

class EmailOrUsernameBackend(BaseBackend):

    def authenticate(self, request, username=None, password=None, **kwargs):

        try:
            # Check if the provided identifier is an email address
            if '@' in username:
                user = User.objects.get(email=username)
            else:
                user = User.objects.get(username=username)

            if user.check_password(password):
                return user
            
        except User.DoesNotExist:

            return None

    def get_user(self, user_id):

        try:

            return User.objects.get(pk=user_id)
        
        except User.DoesNotExist:

            return None