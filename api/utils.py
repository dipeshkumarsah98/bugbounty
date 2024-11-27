import logging
import os
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from .decorators import execute_in_background
import datetime

logger = logging.getLogger(__name__)

def send_email(html_template, context):
    from_email = os.environ.get('EMAIL_ADDRESS')
    subject = context.get('subject')
    to_email = context.get('to_email')
    cc = context.get('cc')
    bcc = context.get('bcc')
    attachments = context.get('attachments')

    if not to_email:
        raise ValueError("The 'to_email' address must be provided and cannot be empty.")
    elif not isinstance(to_email, list):
        to_email = [to_email]

    try:
        html_message = render_to_string(html_template, context)
        message = EmailMessage(subject=subject, body=html_message, from_email=from_email, to=to_email, cc=cc, bcc=bcc,
                               attachments=attachments)
        message.content_subtype = 'html'
        result = message.send()
        logger.info(f"Sending email to {', '.join(to_email)} with subject: {subject} - Status {result}")
    except Exception as e:
        logger.info(f"Sending email to {', '.join(to_email)} with subject: {subject} - Status 0")
        logger.exception(e)

@execute_in_background
def send_otp_email(email, name, otp):
    template = 'emails/otp.html'
    context = {
        'subject': "Your OTP Verification Code",
        'to_email': email,
        'user_name': name,
        'otp_code': otp,
        'current_year': datetime.datetime.now().year,
    }

    send_email(template, context)

@execute_in_background
def send_welcome_email(email, name, role):
    template = 'emails/welcome.html'
    context = {
        'subject': "Welcome to BugBounty Platform!",
        'to_email': email,
        'user_name': name,
        'user_role': role.capitalize(),
        'dashboard_link': 'http://localhost:3000/dashboard/',
        'current_year': datetime.datetime.now().year,
    }

    send_email(template, context)