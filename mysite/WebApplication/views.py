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
	if request.user.is_authenticated:
		return redirect('Features')

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
def RegisterConfirm(request):
	if not request.user.is_authenticated:
		return redirect('Login')
	return render(request, "verify-success.html")

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
	if not request.user.is_authenticated:
		return redirect('Login')
	return render(request, "jjjj.html")

@csrf_exempt
def LoginNewPass(request):
    return render(request, "login-forgot-new-pas.html")

@csrf_exempt
def LoginNewPassSucess(request):
    return render(request, "login-forgot-new-pas-success.html")

@csrf_exempt
def ForgotPassword(request):
    return render(request, "login-forgot.html")

@csrf_exempt
def LoginForgot(request):
    return render(request, "login-forgot-code.html")

@csrf_exempt
def Login(request):
	if request.user.is_authenticated:
		return redirect('Features')
	form = LoginForm()
	return render(request, "login.html", {'form': form})

@csrf_exempt
def Registration(request):
	if request.user.is_authenticated:
		return redirect('Features')

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

@csrf_exempt
def Signout(request):
    logout(request)
    return redirect('Login')

@csrf_exempt
def activate_account(request):
	if request.user.is_authenticated:
		return redirect('Features')
	else:
		try:
			userId = request.session['CurrentUserID']
		except:
			return redirect('Registration')
	if request.method == 'POST':
		ucode = request.POST.get('Ucode')
		userId = request.session['CurrentUserID']
		currentUser = auth.get_user(userId)
		try:
			vcode = currentUser.securitycode
		except(TypeError, ValueError, OverflowError, User.DoesNotExist):
			currentUser = None
		if currentUser is not None:
			if vcode == ucode:
				currentUser.active = True
				currentUser.save()
				login(request, currentUser, backend='django.contrib.auth.backends.ModelBackend')
				del request.session['CurrentUserID']
				return redirect('RegisterConfirm')
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

		try:
			user = auth.authenticate(username=Email, password=Password)
			login(request, user, backend='django.contrib.auth.backends.ModelBackend')
			data = {'isValid':True}
			return JsonResponse(data, status=200)
		except Exception as e:
			print(e)
			data = {'isValid':False}
			return JsonResponse(data, status=200)
	else:
		raise Http404

@csrf_exempt
def RegisterUser(request):
	if request.user.is_authenticated:
		return redirect('Features')
	if request.is_ajax():
		UserForm = RegisterForm(request.POST)
		if UserForm.is_valid():
			#Get all the user information
			FullName = UserForm.cleaned_data['fullname']
			Email = UserForm.cleaned_data['email']
			Password = UserForm.cleaned_data['password']
			try:
				IsUserExist = User.objects.get(email=Email)
				data = {'isValid':False,'Message':"Email already existed!"}
				return JsonResponse(data, status=200)
			except Exception as e:
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
				request.session['CurrentUserID'] = user.pk
				request.session['CurrentUserName'] = FullName
				current_site = get_current_site(request)
				message = render_to_string('Confirmation-Email.html', {
					'user': user,
					'domain': current_site.domain,
					'uid': urlsafe_base64_encode(force_bytes(user.pk)),
					'token': account_activation_token.make_token(user),
					'code' : activation_code
				})
				# send_email.delay(current_site,email_subject,message,Email)
				send_email.delay(message, Email)
				data = {'isValid':True}
				return JsonResponse(data, status=200)
		else:
			data = {'isValid':False}
			return JsonResponse(data, status=200)
	else:
		raise Http404
	 
@csrf_exempt
def resend_code(request):

	User     = get_user_model()
	UserId   = request.session['CurrentUserID']
	user     = User.objects.get(pk=UserId)
	Email    = user.email
	activation_code = randint(1000000, 99999999)
	user.securitycode = activation_code
	user.save()
	current_site = get_current_site(request)
	message = render_to_string('Confirmation-Email.html', {
		'user': user,
		'domain': current_site.domain,
		'uid': urlsafe_base64_encode(force_bytes(user.pk)),
		'token': account_activation_token.make_token(user),
		'code' : activation_code
	})
	send_email.delay(message, Email)
	return render(request, "login-forgot-code.html")

@csrf_exempt
def send_email_forgot_password(request):
	print("send_email_forgot_password")

	if request.is_ajax():
		User     = get_user_model()
		Email    = request.POST['email']

		try:
			user     = User.objects.get(email=Email)
			request.session['CurrentUserID'] = user.pk
			activation_code = randint(1000000, 99999999)
			user.securitycode = activation_code
			user.save()
			current_site = get_current_site(request)
			message = render_to_string('Confirmation-Email.html', {
				'user': user,
				'domain': current_site.domain,
				'uid': urlsafe_base64_encode(force_bytes(user.pk)),
				'token': account_activation_token.make_token(user),
				'code' : activation_code
			})
			send_email.delay(message, Email)
			data = {'isValid':True}
			return JsonResponse(data, status=200)
		except:
			data = {'isValid':False}
			return JsonResponse(data, status=200)
	else:
		raise Http404

@csrf_exempt
def verify_login_forgot_code(request):
	print("verify_login_forgot_code")
	if request.is_ajax():
		User     = get_user_model()
		ucode = request.POST.get('Ucode')
		UserId  = request.session['CurrentUserID']
		user     = User.objects.get(pk=UserId)
		vcode = user.securitycode
		if ucode == vcode:
			data = {'isValid':True}
			return JsonResponse(data, status=200)
		else:
			data = {'isValid':False, 'message':'Please enter correct security code!'}
			return JsonResponse(data, status=200)
	else:
		raise Http404

@csrf_exempt
def save_new_password(request):
	print("save_new_password")
	if request.is_ajax():
		password = request.POST.get('NewPassword')
		cpassword = request.POST.get('CNewPassword')
		if password == cpassword:
			User     = get_user_model()
			UserId  = request.session['CurrentUserID']
			user     = User.objects.get(pk=UserId)
			user.set_password(request.POST["NewPassword"])
			user.save()
			data = {'isValid':True}
			del request.session['CurrentUserID']
			return JsonResponse(data, status=200)
		else:
			data = {'isValid':False, 'message':'Password and Confirm Password should be matched!'}
			return JsonResponse(data, status=200)
	else:
		raise Http404
