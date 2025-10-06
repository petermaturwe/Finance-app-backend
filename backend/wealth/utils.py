from django.core.mail import EmailMessage
import random
import secrets
from django.conf import settings
from .models import *
from django.contrib.sites.shortcuts import get_current_site
import logging
import time
import math
import base64
import requests
from datetime import datetime
from requests.auth import HTTPBasicAuth
from requests import Response
from decimal import Decimal
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string


logging = logging.getLogger("default")

now = datetime.now()
OTP_EXP_MINUTES = 15


def send_password_reset_otp_email(email, request):
    """
    Generate a 6-digit OTP, save it for the user, and email it for password reset.
    """
    user = User.objects.get(email=email)

    # Invalidate previous unused password-reset OTPs (optional but recommended)
    OneTimePassword.objects.filter(
        user=user, is_used=False, purpose=OneTimePassword.Purpose.PASSWORD_RESET
    ).update(is_used=True)

    otp = secrets.randbelow(900000) + 100000  # 6-digit OTP
    OneTimePassword.objects.create(
        user=user,
        otp=str(otp),
        purpose=OneTimePassword.Purpose.PASSWORD_RESET,
        is_used=False,
    )

    subject = "PesaPlus Password Reset Code"
    html_content = render_to_string('otp_email.html', {
        'first_name': user.first_name or 'there',
        'site_name': "PesaPlus",
        'otp': otp,
        'purpose': "Use the verification code below to reset your password.",
        'logo_url': "https://imgur.com/a/cvbugEI",
        'expires_in': OTP_EXP_MINUTES,
        'current_year': timezone.now().year,
    })
    text_content = f"""Hi {user.first_name or 'there'},

You (or someone else) requested to reset your PesaPlus password.
Your verification code is: {otp}

This code expires in {OTP_EXP_MINUTES} minutes.

If you didn't request this, please ignore this email.

PesaPlus Team
"""

    from_email = settings.DEFAULT_FROM_EMAIL
    msg = EmailMultiAlternatives(subject, text_content, from_email, [user.email])
    msg.attach_alternative(html_content, "text/html")
    msg.send()

def send_generated_otp_to_email(email, request): 
    subject = "Your PesaPlus Verification Code"
    otp = secrets.randbelow(900000) + 100000  # 6-digit secure OTP
    current_site = request.get_host()
    user = User.objects.get(email=email)
    
    # DELETE ANY EXISTING UNUSED OTPs FOR THIS USER (EMAIL VERIFICATION PURPOSE)
    # This prevents the unique constraint violation
    OneTimePassword.objects.filter(
        user=user, 
        is_used=False, 
        purpose=OneTimePassword.Purpose.EMAIL_VERIFY
    ).delete()
    
    # Now safely create the new OTP
    OneTimePassword.objects.create(
        user=user, 
        otp=otp,
        purpose=OneTimePassword.Purpose.EMAIL_VERIFY,  # Make sure to specify the purpose
        is_used=False
    )

    html_content = render_to_string('otp_email.html', {
        'first_name': user.first_name,
        'site_name': "PesaPlus",
        'otp': otp,
        'logo_url': "https://imgur.com/a/cvbugEI",  
        'purpose': "Use the verification code below to verify your email address.",
        'expires_in': OTP_EXP_MINUTES,
        'current_year': timezone.now().year,
    })
    text_content = f"Hi {user.first_name},\nThank you for signing up at PesaPlus!\nYour OTP is: {otp}\nThis code expires in {OTP_EXP_MINUTES} minutes.\n"
    from_email = settings.DEFAULT_FROM_EMAIL
    msg = EmailMultiAlternatives(subject, text_content, from_email, [user.email])
    msg.attach_alternative(html_content, "text/html")
    msg.send()

def send_normal_email(data):
    """
    Sends a normal email using the provided data dictionary.
    
    Args:
        data: Dictionary containing email_body, email_subject, to_email
    """
    subject = data['email_subject']
    
    # Extract the user's first name and actual reset link from the email_body
    # The email_body format is: f"Hi {user.first_name} use the link below to reset your password {abslink}"
    email_body = data['email_body']
    first_name = email_body.split("Hi ")[1].split(" use")[0]
    reset_link = email_body.split("reset your password ")[1]
    
    context = {
        'first_name': first_name,
        'reset_link': reset_link,
        'site_name': "PesaPlus",
        'logo_url': "https://imgur.com/a/cvbugEI",
        'current_year': timezone.now().year
    }
    
    html_content = render_to_string('password_reset_email.html', context)
    text_content = f"Hi {first_name},\n\nWe received a request to reset your password for your PesaPlus account. Click the link below to set a new password:\n\n{reset_link}\n\nThis link will expire in 15 minutes.\n\nIf you didn't request this password reset, please ignore this email or contact support.\n\nPesaPlus Team"
    
    from_email = settings.DEFAULT_FROM_EMAIL
    to_email = data['to_email']
    
    msg = EmailMultiAlternatives(subject, text_content, from_email, [to_email])
    msg.attach_alternative(html_content, "text/html")
    msg.send()

def calculate_repayment_schedule(debts, extra_monthly=Decimal('0.0'), extra_yearly=Decimal('0.0'), strategy='avalanche'):
    # Sort debts initially based on the strategy
    debts = sorted(debts, key=lambda d: (
        -d['interest_rate'] if strategy == 'avalanche'
        else d['remaining_balance'] if strategy == 'snowball'
        else 0
    ))

    print(f"Starting calculation for {len(debts)} debts with strategy: {strategy}")
    total_interest_paid = Decimal('0.0')
    month = 0
    schedule = []
    
    # Set a reasonable maximum (50 years = 600 months)
    MAX_MONTHS = 600
    
    # Define a small threshold to consider debt paid off (to avoid floating point precision issues)
    PAYOFF_THRESHOLD = Decimal('0.01')
    
    # Calculate initial total debt
    initial_total_debt = sum(d['remaining_balance'] for d in debts)
    print(f"Initial total debt: {initial_total_debt}")
    
    # Track progress to detect stalls
    last_total_remaining = initial_total_debt
    stalled_count = 0
    
    # Clear really small balances first to avoid precision issues
    for d in debts:
        if d['remaining_balance'] < PAYOFF_THRESHOLD:
            d['remaining_balance'] = Decimal('0.0')

    while any(d['remaining_balance'] > PAYOFF_THRESHOLD for d in debts):
        month += 1
        
        # Safety check - don't calculate beyond 50 years
        if month > MAX_MONTHS:
            print(f"WARNING: Reached maximum months ({MAX_MONTHS}), stopping calculation")
            break
            
        # Log progress every year
        if month % 12 == 0:
            total_remaining = sum(d['remaining_balance'] for d in debts)
            percent_paid = 100 * (1 - total_remaining / initial_total_debt) if initial_total_debt > 0 else 100
            print(f"Year {month//12}: {percent_paid:.1f}% paid off, {total_remaining:.2f} remaining")
            
            # Detect if we're making very little progress (indicating a potential stall)
            progress = last_total_remaining - total_remaining
            if progress < Decimal('1.0'):  # Less than $1 progress in a year
                stalled_count += 1
                if stalled_count >= 3:  # If stalled for 3 years
                    print("WARNING: Calculation appears stalled (minimal progress). Stopping.")
                    break
            else:
                stalled_count = 0  # Reset stall counter if we're making progress
                
            last_total_remaining = total_remaining

        # Apply yearly extra payment at the first month of each year
        year_bonus = extra_yearly if month % 12 == 1 else Decimal('0.0')

        # Step 1: Pay minimum payments and interest
        for d in debts:
            if d['remaining_balance'] <= PAYOFF_THRESHOLD:
                d['remaining_balance'] = Decimal('0.0')
                continue

            interest = d['remaining_balance'] * (d['interest_rate'] / Decimal('100')) / 12
            min_payment = d['monthly_min_payment']
            
            # Ensure minimum payment is at least interest plus some principal
            min_payment_floor = interest + Decimal('1.0')
            if min_payment < min_payment_floor and d['remaining_balance'] > Decimal('100'):
                # Adjust very low minimum payments to avoid infinite loop
                print(f"Adjusting minimum payment for {d['name']} from {min_payment} to {min_payment_floor}")
                min_payment = min_payment_floor
                
            actual_payment = min(min_payment, d['remaining_balance'] + interest)
            principal_payment = actual_payment - interest
            
            if principal_payment < 0:
                principal_payment = Decimal('0.0')  # Avoid negative principal payment

            d['remaining_balance'] -= principal_payment
            total_interest_paid += interest

        # Step 2: Pool all extra payments
        total_extra = year_bonus
        for d in debts:
            total_extra += Decimal(str(d.get('extra_monthly_payment', '0.0')))

        # Step 3: Apply extra payments to highest priority debts
        active_debts = [d for d in debts if d['remaining_balance'] > PAYOFF_THRESHOLD]
        
        # Re-sort active debts according to strategy for applying extra payments
        active_debts.sort(key=lambda d: (
            -d['interest_rate'] if strategy == 'avalanche'
            else d['remaining_balance'] if strategy == 'snowball'
            else 0
        ))
        
        for d in active_debts:
            if total_extra <= 0:
                break
                
            extra_payment = min(total_extra, d['remaining_balance'])
            d['remaining_balance'] -= extra_payment
            total_extra -= extra_payment

        # Only save monthly data for certain months to reduce data size
        if month <= 24 or month % 3 == 0 or month >= MAX_MONTHS - 3:
            schedule.append({
                'month': month,
                'total_remaining': float(sum([max(Decimal('0'), d['remaining_balance']) for d in debts])),
                'total_interest_paid': float(total_interest_paid)
            })

    # Set final statuses
    for d in debts:
        d['remaining_balance'] = max(Decimal('0'), d['remaining_balance'])
        d['status'] = 'paid' if d['remaining_balance'] <= PAYOFF_THRESHOLD else 'active'

    print(f"Calculation complete in {month} months with {float(total_interest_paid)} interest paid")
    
    # Return a smaller schedule if it's very large
    if len(schedule) > 100:
        # Keep first year monthly, then quarterly
        reduced_schedule = [
            s for s in schedule if s['month'] <= 12 or s['month'] % 3 == 0 or s['month'] >= month - 3
        ]
        print(f"Reduced schedule from {len(schedule)} to {len(reduced_schedule)} points")
        schedule = reduced_schedule

    return {
        'months_to_payoff': month,
        'total_interest_paid': float(total_interest_paid),
        'schedule': schedule,
        'final_debt_states': [
            {
                'name': d['name'],
                'remaining_balance': float(d['remaining_balance']),
                'status': d['status']
            }
            for d in debts
        ]
    }

def investment_schedule(data):
    schedule_type = data['schedule_type']
    start = data['starting_amount']
    rate = data['return_rate'] / 100
    contrib = data['additional_contribution']
    years = data['years']
    contribute_at = data['contribute_at']
    compound = data['compound']

    schedule = []
    total_balance = start
    total_interest = 0

    if schedule_type == 'monthly':
        for month in range(1, years * 12 + 1):
            if contribute_at == 'beginning':
                total_balance += contrib

            if compound == 'monthly':
                monthly_rate = rate / 12
                interest = total_balance * monthly_rate
                total_balance += interest
                total_interest += interest

            elif compound == 'annually':
                # Use monthly-effective rate based on annual rate
                monthly_effective_rate = (1 + rate) ** (1 / 12) - 1
                interest = total_balance * monthly_effective_rate
                total_balance += interest
                total_interest += interest

            if contribute_at == 'end':
                total_balance += contrib

            schedule.append({
                "month": month,
                "deposit": round(contrib, 2),
                "interest": round(interest, 2),
                "ending_balance": round(total_balance, 2)
            })

    elif schedule_type == 'annual':
        for year in range(1, years + 1):
            interest_for_year = 0
            for month in range(12):
                if contribute_at == 'beginning':
                    total_balance += contrib

                if compound == 'monthly':
                    monthly_rate = rate / 12
                    interest = total_balance * monthly_rate
                elif compound == 'annually':
                    monthly_rate = (1 + rate) ** (1 / 12) - 1
                    interest = total_balance * monthly_rate
                else:
                    interest = 0

                total_balance += interest
                total_interest += interest
                interest_for_year += interest

                if contribute_at == 'end':
                    total_balance += contrib

            schedule.append({
                "year": year,
                "deposit": round(contrib * 12, 2),
                "interest": round(interest_for_year, 2),
                "ending_balance": round(total_balance, 2)
            })
            
    return schedule
#Financial Wellness Start
def compute_path(initial_capital, savings, roi, expenses, inflation, max_years=100):
    savings_total = initial_capital
    year = 0

    while year < max_years and savings_total * roi < expenses:
        net_savings = (savings * 12) - expenses
        savings_total += net_savings + (savings_total * roi)
        savings_total /= (1 + inflation)
        year += 1

    meets_wellness = savings_total * roi >= expenses
    savings_income = savings_total * roi if meets_wellness else 0

    return {
        "year": (year + 1) if meets_wellness and year == 0 else (year if meets_wellness else None),
        "savings_total": round(savings_total, 2),
        "savings_income": round(savings_income, 2)
    }

def run_scenarios(projection):
    # Helper for percent to decimal
    def to_decimal(val):
        return float(val) / 100.0

    # Helper to get float from list index
    def get_num(arr, idx):
        return float(arr[idx])

    # Get min and max for each range
    savings_min = get_num(projection.savings_range["lower"], 0)
    savings_max = get_num(projection.savings_range["upper"], -1)
    roi_min = to_decimal(get_num(projection.roi_range["lower"], 0))
    roi_max = to_decimal(get_num(projection.roi_range["upper"], -1))
    expense_min = get_num(projection.expense_range["lower"], 0)
    expense_max = get_num(projection.expense_range["upper"], -1)
    inflation_min = to_decimal(get_num(projection.inflation_range["lower"], 0))
    inflation_max = to_decimal(get_num(projection.inflation_range["upper"], -1))

    # Averages
    savings_avg = (savings_min + savings_max) / 2
    roi_avg = (roi_min + roi_max) / 2
    expense_avg = (expense_min + expense_max) / 2
    inflation_avg = (inflation_min + inflation_max) / 2

    fastest = compute_path(
        float(projection.initial_capital),
        savings_max,
        roi_max,
        expense_min,
        inflation_min
    )
    slowest = compute_path(
        float(projection.initial_capital),
        savings_min,
        roi_min,
        expense_max,
        inflation_max
    )
    avg = compute_path(
        float(projection.initial_capital),
        savings_avg,
        roi_avg,
        expense_avg,
        inflation_avg
    )

    return {
        "fastest_path": fastest,
        "slowest_path": slowest,
        "average_path": avg,
    }
    