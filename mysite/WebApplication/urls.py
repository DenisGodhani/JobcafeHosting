from django.conf.urls import url
from . import views

urlpatterns = [
	url(r'^$',                  views.index ,                    name="index"),
	url(r'^register$',          views.Registration ,             name="Registration"),
	url(r'^login$',             views.Login ,                    name="Login"),
	url(r'^logout$',            views.Signout ,                  name="Signout"),
	url(r'^activate$',          views.activate_account ,         name="AccountActivation"),
	url(r'^payment$',           views.Payment ,                  name="Payment"),
	url(r'^payment2$',          views.Payment2 ,                 name="Payment2"),
	url(r'^termscondition$',    views.TermsConditions ,          name="TermsConditions"),
	url(r'^pricingplans$',      views.Pricing ,                  name="Pricing"),
	url(r'^confirmation$',      views.Confirmation ,             name="Confirmation"),
	url(r'^feature$',           views.Features ,                 name="Features"),
	url(r'^ajax/registeruser$', views.RegisterUser ,             name="RegisterUser"),
	url(r'^forgot-password',    views.ForgotPassword ,           name="ForgotPass"),
	url(r'^ajax/validateUse',   views.validateUser ,             name="ValidateUser"),
	# url(r'^ajax/sendcode',      views.sendcode ,                 name="Sendcode")
]
