from __future__ import absolute_import
from celery import shared_task
from django.core.mail import EmailMessage
from celery.utils.log import get_task_logger

logger=get_task_logger(__name__)

@shared_task  # Use this decorator to make this a asyncronous function
def send_email(message, email):
    email_subject = 'Activate Your Account'
    email = EmailMessage(email_subject, message, to=[email])
    email.content_subtype = 'html'
    email.send()
    logger.info("Sent email")
