from django import forms
import re
from .models import User
from django.core.validators import RegexValidator

# Regex for fullname and email address.
Fullname_Validator = RegexValidator(r"\s", "Full name should contain Atleast one space")
Email_Validator    = RegexValidator(r"^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$", "Invalid Email")

class RegisterForm(forms.Form):

    fullname    = forms.CharField(widget = forms.TextInput(attrs={'class':'form-input','id':'fullname'}), validators=[Fullname_Validator])
    email       = forms.CharField(widget = forms.TextInput(attrs={'class':'form-input','id':'email'}),    validators=[Email_Validator])
    password    = forms.CharField(widget = forms.PasswordInput(attrs={'class':'form-input','id':'password'}))
    cpassword   = forms.CharField(widget = forms.PasswordInput(attrs={'class':'form-input','id':'cpassword'}))
    
    class Meta:
        model = User
        fields = ['fullname','email','password']

    def clean(self):
        cleaned_data = super(RegisterForm, self).clean()
        full_name    = cleaned_data.get("fullname")
        password     = cleaned_data.get("password")
        confirm_password = cleaned_data.get("cpassword")

        if password != confirm_password:
            raise forms.ValidationError(
                "Password and Confirm Password does not match"
            )
    

class LoginForm(forms.Form):
    Email       = forms.CharField(widget = forms.EmailInput(attrs={'class':'form-input','id':'Email','placeholder':'Username or email address'}))
    Password    = forms.CharField(widget = forms.PasswordInput(attrs={'class':'form-input','id':'Password','placeholder':'Password'}))

