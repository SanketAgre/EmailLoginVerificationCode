from django.contrib.auth.forms import UserCreationForm,PasswordChangeForm

from .models import User
from django import forms
# change password with old password



# custom user registration form 
class Costomuserform(UserCreationForm):
    username=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control my2','placeholder':'Enter Username'}))
    email=forms.CharField(widget=forms.EmailInput(attrs={'class':'form-control my2','placeholder':'Enter Email'}))
    password1=forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control my2','placeholder':'Enter Password'}))
    password2=forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control my2','placeholder':'Confirm Password'}))
    class Meta:
        model=User
        fields=['username','email','password1','password2',]


# change password use old password form
class UserPasswordChangeForm(PasswordChangeForm):
    old_password=forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control my2','placeholder':'Enter Old Password'}))
    new_password1=forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control my2','placeholder':'Enter new Password'}))
    new_password2=forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control my2','placeholder':'Confirm Password'}))
    
    class Meta:
        model=User
        fields=['old_password','new_password1','new_password2',]

# forget password form 
class UserforgetPassword(forms.Form):
    username=forms.CharField(widget=forms.TextInput(attrs={'class':'form-control my2','placeholder':'Enter Username'}))
    
    class Meta:
        model=User
        fields=['username']

# User Change Password form 
class UserChangePassword(forms.Form):
    new_password1=forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control my2','placeholder':'Enter new Password'}))
    new_password2=forms.CharField(widget=forms.PasswordInput(attrs={'class':'form-control my2','placeholder':'Confirm Password'}))
    
    class Meta:
        model=User
        fields=['new_password1','new_password2']


