import logging
from decimal import Decimal
import os
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.db.models import Sum, Q
from .models import RewardTransaction
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

@execute_in_background
def send_reward_email(email, name, amount, title):
    template = 'emails/bug_reward.html'
    context = {
        'subject': "Congratulations! You've received a reward",
        'to_email': email,
        'bug_title': title,
        'user_name': name,
        'rewarded_amount': amount,
        'current_year': datetime.datetime.now().year,
    }

    send_email(template, context)

@execute_in_background
def send_bug_rejected_email(email, name, title):
    template = 'emails/bug_rejected.html'
    context = {
        'subject': "Your Bug Report has been Rejected",
        'to_email': email,
        'bug_title': title,
        'user_name': name,
        'current_year': datetime.datetime.now().year,
    }

    send_email(template, context)

@execute_in_background
def send_withdrawal_email(email, name, amount, trans_id):
    template = 'emails/withdrawal.html'
    context = {
        'subject': "Withdrawal Request Received",
        'to_email': email,
        'user_name': name,
        'amount': amount,
        'transaction_id': trans_id,
        'current_year': datetime.datetime.now().year,
    }
    
    send_email(template, context)

def get_user_balance(user):
    if not user:
        return Decimal('0')

    aggregate_data = RewardTransaction.objects.filter(user=user).aggregate(
        total_credits=Sum('amount', filter=Q(transaction_type='credit')),
        total_debits=Sum('amount', filter=Q(transaction_type='debit'))
    )
    total_credits = aggregate_data['total_credits'] or Decimal('0')
    total_debits = aggregate_data['total_debits'] or Decimal('0')

    return dict(
        total_credits=total_credits,
        total_debits=total_debits,
        balance=total_credits - total_debits
    )