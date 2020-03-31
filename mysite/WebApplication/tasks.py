from __future__ import absolute_import
from celery import shared_task
from django.core.mail import EmailMessage

@shared_task  # Use this decorator to make this a asyncronous function
def send_email(email_subject, message, email):
    email = EmailMessage(email_subject, message, to=[email])
    email.content_subtype = 'html'
    email.send()
