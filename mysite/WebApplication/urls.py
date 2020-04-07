from django.conf.urls import url
from . import views

urlpatterns = [
	url(r'^$',                  views.index ,                    name="index"),
	url(r'^register$',          views.Registration ,             name="Registration"),
	url(r'^login$',             views.Login ,                    name="Login"),
	url(r'^logout$',            views.Signout ,                  name="Signout"),
	url(r'^activate$',          views.activate_account ,         name="AccountActivation"),
	url(r'^confirm$',           views.RegisterConfirm ,          name="RegisterConfirm"),
	url(r'^payment$',           views.Payment ,                  name="Payment"),
	url(r'^payment2$',          views.Payment2 ,                 name="Payment2"),
	url(r'^termscondition$',    views.TermsConditions ,          name="TermsConditions"),
	url(r'^pricingplans$',      views.Pricing ,                  name="Pricing"),
	url(r'^confirmation$',      views.Confirmation ,             name="Confirmation"),
	url(r'^feature$',           views.Features ,                 name="Features"),
	url(r'^loginforgot$',       views.LoginForgot ,              name="LoginForgot"),
	url(r'^loginnewpass$',      views.LoginNewPass ,              name="LoginNewPass"),
	url(r'^loginnewpasssucess$', views.LoginNewPassSucess ,              name="LoginNewPassSucess"),
	url(r'^ajax/sendemailforgotpass$',  views.send_email_forgot_password,name="send_email_forgot_password"),
	url(r'^ajax/verifyloginforgotcode$',  views.verify_login_forgot_code,name="verify_login_forgot_code"),
	url(r'^ajax/savenewpassword$',  views.save_new_password,name="save_new_password"),
	url(r'^ajax/registeruser$', views.RegisterUser ,             name="RegisterUser"),
	url(r'^forgot-password',    views.ForgotPassword ,           name="ForgotPass"),
	url(r'^ajax/validateUse',   views.validateUser ,             name="ValidateUser"),
	url(r'^resendcode',      views.resend_code ,                 name="resend_code")
]
