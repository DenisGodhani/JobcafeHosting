from django.shortcuts import render, redirect, reverse
from django.views.decorators.csrf import csrf_exempt
from django.http import HttpResponse
from django.conf import settings
import os
import json
from django.http import Http404
from django.http import JsonResponse
from .forms import RegisterForm
from django.utils import timezone
from .forms import LoginForm
from django.shortcuts import render, redirect
from django.contrib.auth import login, logout
from django.contrib.auth.forms import AuthenticationForm
from .backends import EmailAuthBackend
from django.contrib.auth import authenticate
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .token_generator import account_activation_token
from django.contrib.auth import get_user_model
from django.contrib.auth.decorators import login_required
from random import randint
from .tasks import send_email
User = get_user_model()
auth = EmailAuthBackend()
# Create your views here.

@csrf_exempt
def index(request):
    UserForm = RegisterForm()
    if request.method == 'POST':
        request.session['UserForm'] = request.POST
        return redirect('Registration')
    return render(request, "index.html", {'form': UserForm})

@csrf_exempt
def Verify(request):
    return render(request, "verify.html")

@csrf_exempt
def Pricing(request):
    return render(request, "pricing.html")

@csrf_exempt
def Payment(request):
    return render(request, "pyment.html")

@csrf_exempt
def TermsConditions(request):
    return render(request, "yy- terms-conditions.html")

@csrf_exempt
def Payment2(request):
    return render(request, "pyment-2.html")

@csrf_exempt
def Confirmation(request):
    return render(request, "confirmation.html")

@csrf_exempt
def Features(request):
    return render(request, "jjjj.html")

@csrf_exempt
def ForgotPassword(request):
    return render(request, "login-forgot.html")

@csrf_exempt
def Login(request):
	form = LoginForm()
	return render(request, "login.html", {'form': form})

@csrf_exempt
def Registration(request):

	try:
	#If redirect from Index page
		if request.session['UserForm']:
			regform = RegisterForm(request.session.pop('UserForm'))
			regform.fields['password'].widget.render_value  = True
			regform.fields['cpassword'].widget.render_value = True
			return render(request, "register1.html", {'form': regform})
	except:
		#Direct request for register page
		UserForm = RegisterForm()
		return render(request, "register1.html", {'form': UserForm})

	# if request.method == 'POST':
	# 	UserForm = RegisterForm(request.POST)
	# 	if UserForm.is_valid():
	# 		#Get all the user information
	# 		FullName = UserForm.cleaned_data['fullname']
	# 		Email = UserForm.cleaned_data['email']
	# 		Password = UserForm.cleaned_data['password']
	# 		activation_code = randint(1000000, 99999999)
	# 		#Save User info into User table
	# 		authUser = User(email=Email, fullname=FullName, securitycode=activation_code)
	# 		authUser.set_password(request.POST["password"])
	# 		authUser.last_login = timezone.now()
	# 		authUser.active = False
	# 		authUser.save()
	# 		#Use Custom Email User Authenticator to authenticate and log user
	# 		user = auth.authenticate(username=Email, password=Password)
	# 		login(request, user, backend='django.contrib.auth.backends.ModelBackend')
	# 		current_site = get_current_site(request)
	# 		email_subject = 'Activate Your Account'
	# 		message = render_to_string('Confirmation-Email.html', {
	# 			'user': user,
	# 			'domain': current_site.domain,
	# 			'uid': urlsafe_base64_encode(force_bytes(user.pk)),
	# 			'token': account_activation_token.make_token(user),
	# 			'code' : activation_code
	# 		})
	# 		email = EmailMessage(email_subject, message, to=[Email])
	# 		email.content_subtype = 'html'
	# 		email.send()
	# 		return redirect('AccountActivation')
	# 	else:
	# 		# If wrong details supplied by user while registration
	# 		UserForm.fields['password'].widget.render_value  = True
	# 		UserForm.fields['cpassword'].widget.render_value = True
	# 		return render(request, "register1.html", {'form': UserForm})
	# else:
	# 	try:
	# 		#If redirect from Index page
	# 		if request.session['UserForm']:
	# 			regform = RegisterForm(request.session.pop('UserForm'))
	# 			regform.fields['password'].widget.render_value  = True
	# 			regform.fields['cpassword'].widget.render_value = True
	# 			return render(request, "register1.html", {'form': regform})
	# 	except:
	# 		#Direct request for register page
	# 		UserForm = RegisterForm()
	# 		return render(request, "register1.html", {'form': UserForm})

@csrf_exempt
def Signout(request):
    logout(request)
    return redirect('Login')

@csrf_exempt
def activate_account(request):
	if request.method == 'POST':
		ucode = request.POST.get('Ucode')
		try:
			vcode = request.user.securitycode
			user = request.user
		except(TypeError, ValueError, OverflowError, User.DoesNotExist):
			user = None
		if user is not None:
			if vcode == ucode:
				user.active = True
				user.save()
				login(request, user, backend='django.contrib.auth.backends.ModelBackend')
				return render(request, "verify-success.html")
			else:
				return render(request, "verify.html", {'Error':True, 'Message':'Please enter correct security code!'})
		else:
			return render(request, "verify.html", {'Error':True, 'Message':'Something went wrong while activate your account!'})
	else:
		return render(request, "verify.html", {'Error':False})

@csrf_exempt
def validateUser(request):
	if request.is_ajax():
		Email    = request.POST['Email']
		Password = request.POST['Password']
		user = auth.authenticate(username=Email, password=Password)
		if user is not None:
			login(request, user, backend='django.contrib.auth.backends.ModelBackend')
			data = {'isValid':True}
			return JsonResponse(data, status=200)
		else:
			data = {'isValid':False}
			return JsonResponse(data, status=200)
	else:
		raise Http404

@csrf_exempt
def RegisterUser(request):
	if request.is_ajax():
		UserForm = RegisterForm(request.POST)
		if UserForm.is_valid():
			#Get all the user information
			FullName = UserForm.cleaned_data['fullname']
			Email = UserForm.cleaned_data['email']
			Password = UserForm.cleaned_data['password']
			activation_code = randint(1000000, 99999999)
			#Save User info into User table
			authUser = User(email=Email, fullname=FullName, securitycode=activation_code)
			authUser.set_password(request.POST["password"])
			authUser.last_login = timezone.now()
			authUser.active = False
			authUser.save()
			#Use Custom Email User Authenticator to authenticate and log user
			user = auth.authenticate(username=Email, password=Password)
			login(request, user, backend='django.contrib.auth.backends.ModelBackend')
			current_site = get_current_site(request)
			print(current_site.domain)
			email_subject = 'Activate Your Account'
			message = render_to_string('Confirmation-Email.html', {
				'user': user,
				'domain': current_site.domain,
				'uid': urlsafe_base64_encode(force_bytes(user.pk)),
				'token': account_activation_token.make_token(user),
				'code' : activation_code
			})
			# send_email.delay(current_site,email_subject,message,Email)
			X = send_email.delay(email_subject, message, Email)
			print("Email Is Sent")
			# current_site = get_current_site(request)
			# email_subject = 'Activate Your Account'
			# message = render_to_string('Confirmation-Email.html', {
			# 	'user': user,
			# 	'domain': current_site.domain,
			# 	'uid': urlsafe_base64_encode(force_bytes(user.pk)),
			# 	'token': account_activation_token.make_token(user),
			# 	'code' : activation_code
			# })
			# email = EmailMessage(email_subject, message, to=[Email])
			# email.content_subtype = 'html'
			# email.send()
			data = {'isValid':True}
			return JsonResponse(data, status=200)
		else:
			print("Not valiiiiiiiddd........")
			# If wrong details supplied by user while registration
			# UserForm.fields['password'].widget.render_value  = True
			# UserForm.fields['cpassword'].widget.render_value = True
			data = {'isValid':False}
			return JsonResponse(data, status=200)
	else:
		raise Http404
	 
@csrf_exempt
def sendcode(request):

	if request.is_ajax():
		User = get_user_model()
		Email    = request.POST['Email']
		user     = User.objects.get(email=Email)
		activation_code = randint(1000000, 99999999)
		print(request.user)
	else:
		raise Http404