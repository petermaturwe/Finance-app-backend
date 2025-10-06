from django.shortcuts import render
from wealth.serializers import *
from rest_framework import generics, permissions, status, generics,  viewsets
from rest_framework.generics import GenericAPIView
from rest_framework.response import Response
from rest_framework.decorators import action, api_view, permission_classes
from wealth.models import *
from django.conf import settings
from .utils import send_generated_otp_to_email
from rest_framework import status
from django.utils.encoding import smart_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_decode
from rest_framework.exceptions import ValidationError
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.views import APIView
from rest_framework_simplejwt.serializers import TokenRefreshSerializer
from rest_framework_simplejwt.views import TokenRefreshView

from .utils import calculate_repayment_schedule
from decimal import Decimal
from .utils import investment_schedule

from rest_framework import generics
from .models import InvestmentCalculation
from .serializers import InvestmentCalculationSerializer
from .utils import investment_schedule
from rest_framework.generics import RetrieveUpdateDestroyAPIView

from django.shortcuts import get_object_or_404
from .utils import run_scenarios
from django.db.models import Sum
from django.db import transaction
import random
import time
import logging
import os
from datetime import timedelta
from django.core.mail import send_mail
from django.http import JsonResponse


logger = logging.getLogger(__name__)



class RegisterView(GenericAPIView):
    serializer_class = UserRegisterSerializer

    def post(self, request):
        user_data = request.data
        serializer = self.serializer_class(data=user_data)
        
        try:
            if serializer.is_valid(raise_exception=True):
                # Check if user already exists
                email = serializer.validated_data.get('email')
                if User.objects.filter(email=email).exists():
                    existing_user = User.objects.get(email=email)
                    if existing_user.is_verified:
                        return Response({
                            'type': 'user_exists',
                            'message': 'An account with this email already exists. Please try logging in instead.',
                            'action': 'login'
                        }, status=status.HTTP_409_CONFLICT)
                    else:
                        # User exists but not verified, resend OTP
                        send_generated_otp_to_email(email, request)
                        return Response({
                            'type': 'resend_verification',
                            'message': 'You already have an account. A new verification code has been sent to your email.',
                            'email': email,
                            'action': 'verify'
                        }, status=status.HTTP_200_OK)
                
                # Create new user
                serializer.save()
                user_data = serializer.data
                send_generated_otp_to_email(user_data['email'], request)
                return Response({
                    'type': 'registration_success',
                    'data': user_data,
                    'message': 'Registration successful! A verification code has been sent to your email.',
                    'email': user_data['email'],
                    'action': 'verify'
                }, status=status.HTTP_201_CREATED)
                
        except Exception as e:
            if 'email' in str(e).lower() and 'already exists' in str(e).lower():
                return Response({
                    'type': 'user_exists',
                    'message': 'An account with this email already exists. Please try logging in instead.',
                    'action': 'login'
                }, status=status.HTTP_409_CONFLICT)
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class VerifyUserEmail(GenericAPIView):
    def post(self, request):
        try:
            passcode = request.data.get('otp')
            email = request.data.get('email')
            
            if not passcode:
                return Response({
                    'type': 'missing_otp',
                    'message': 'Verification code is required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Find the OTP record
            try:
                user_pass_obj = OneTimePassword.objects.get(otp=passcode)
                user = user_pass_obj.user
                
                # Verify email matches if provided
                if email and user.email != email:
                    return Response({
                        'type': 'invalid_otp',
                        'message': 'Invalid verification code'
                    }, status=status.HTTP_400_BAD_REQUEST)
                
            except OneTimePassword.DoesNotExist:
                return Response({
                    'type': 'invalid_otp',
                    'message': 'Invalid or expired verification code'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            if not user.is_verified:
                user.is_verified = True
                user.save()
                
                # Delete used OTP
                user_pass_obj.delete()
                
                # Generate tokens for the user
                tokens = user.tokens()
                
                return Response({
                    'type': 'verification_success',
                    'message': 'Email verified successfully! Welcome to WealthPro.',
                    'tokens': tokens,
                    'user': {
                        'email': user.email,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'is_verified': True
                    }
                }, status=status.HTTP_200_OK)
            else:
                # User already verified, delete the OTP and return tokens
                user_pass_obj.delete()
                tokens = user.tokens()
                
                return Response({
                    'type': 'already_verified',
                    'message': 'Account already verified. You can now use the app!',
                    'tokens': tokens,
                    'user': {
                        'email': user.email,
                        'first_name': user.first_name,
                        'last_name': user.last_name,
                        'is_verified': True
                    }
                }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'type': 'verification_error',
                'message': 'An error occurred during verification. Please try again.'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
            
class ResendOTPView(GenericAPIView):
    """Resend OTP for email verification"""
    
    def post(self, request):
        email = request.data.get('email')
        
        if not email:
            return Response({
                'type': 'missing_email',
                'message': 'Email is required'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = User.objects.get(email=email)
            if user.is_verified:
                return Response({
                    'type': 'already_verified',
                    'message': 'Your account is already verified. You can login now.'
                }, status=status.HTTP_200_OK)
            
            # Delete old OTPs for this user
            OneTimePassword.objects.filter(user=user).delete()
            
            # Send new OTP
            send_generated_otp_to_email(email, request)
            
            return Response({
                'type': 'otp_sent',
                'message': 'A new verification code has been sent to your email.',
                'email': email
            }, status=status.HTTP_200_OK)
            
        except User.DoesNotExist:
            return Response({
                'type': 'user_not_found',
                'message': 'No account found with this email address.'
            }, status=status.HTTP_404_NOT_FOUND)


class LoginUserView(GenericAPIView):
    serializer_class = LoginSerializer
    
    def post(self, request):
        email = request.data.get('email')
        password = request.data.get('password')
        
        # Check if user exists
        try:
            user = User.objects.get(email=email)
            if not user.is_verified:
                # User exists but not verified, send new OTP
                send_generated_otp_to_email(email, request)
                return Response({
                    'type': 'email_not_verified',
                    'message': 'Your account is not verified. A new verification code has been sent to your email.',
                    'email': email,
                    'action': 'verify'
                }, status=status.HTTP_403_FORBIDDEN)
        except User.DoesNotExist:
            # Continue with normal flow to avoid email enumeration
            pass
        
        # Process normal login
        serializer = self.serializer_class(data=request.data, context={'request': request})
        try:
            serializer.is_valid(raise_exception=True)
            return Response({
                'type': 'login_success',
                'data': serializer.data,
                'message': 'Login successful!'
            }, status=status.HTTP_200_OK)
        except AuthenticationFailed as e:
            error_message = str(e)
            if 'not verified' in error_message.lower():
                # Send new OTP for unverified users
                if User.objects.filter(email=email).exists():
                    send_generated_otp_to_email(email, request)
                    return Response({
                        'type': 'email_not_verified',
                        'message': 'Your account is not verified. A new verification code has been sent to your email.',
                        'email': email,
                        'action': 'verify'
                    }, status=status.HTTP_403_FORBIDDEN)
            
            return Response({
                'type': 'invalid_credentials',
                'message': 'Invalid email or password. Please check your credentials and try again.',
                'action': 'retry'
            }, status=status.HTTP_401_UNAUTHORIZED)



# Keep existing password reset views unchanged
class CheckEmailExistsView(GenericAPIView):
    def post(self, request):
        email = request.data.get('email')
        if not email:
            return Response(
                {'error': 'Email is required'}, 
                status=status.HTTP_400_BAD_REQUEST
            )
        
        exists = User.objects.filter(email=email).exists()
        return Response(
            {'exists': exists, 'message': 'Email found' if exists else 'Email not found'}, 
            status=status.HTTP_200_OK
        )

class PasswordResetRequestView(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = PasswordResetRequestSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        # Always return success to avoid enumeration
        return Response({
            'success': True,
            'message': 'If an account with this email exists, a verification code has been sent.'
        }, status=status.HTTP_200_OK)


class VerifyOTPView(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = VerifyOTPSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        return Response({'success': True, 'message': 'Code verified'}, status=status.HTTP_200_OK)


class SetNewPasswordOTPView(GenericAPIView):
    permission_classes = [AllowAny]
    serializer_class = SetNewPasswordOTPSerializer

    def post(self, request):
        serializer = self.serializer_class(data=request.data, context={'request': request})
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({'success': True, 'message': 'Password has been reset successfully'}, status=status.HTTP_200_OK)
class LogoutApiView(GenericAPIView):

   
    serializer_class=LogoutUserSerializer
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer=self.serializer_class(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response({"message": "Logout successful."})
 
class UserProfileView(APIView):
    """
    API View to retrieve and update user profile
    """
    permission_classes = [IsAuthenticated]
    
    def get(self, request):
        """
        Retrieve user profile information
        """
        user = request.user
        serializer = UserProfileSerializer(user)
        return Response(serializer.data)
    
    def patch(self, request):
        """
        Update user profile information
        """
        user = request.user
        serializer = UserProfileUpdateSerializer(user, data=request.data, partial=True)
        
        if serializer.is_valid():
            serializer.save()
            return Response(UserProfileSerializer(user).data)
        
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ChangePasswordView(APIView):
    """
    API View to change user password
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        serializer = ChangePasswordSerializer(data=request.data)
        
        if serializer.is_valid():
            # Check if current password is correct
            user = request.user
            current_password = serializer.validated_data['current_password']
            new_password = serializer.validated_data['new_password']
            
            if not user.check_password(current_password):
                return Response(
                    {"error": "Current password is incorrect"}, 
                    status=status.HTTP_400_BAD_REQUEST
                )
            
            # Set new password
            user.set_password(new_password)
            user.save()
            
            return Response(
                {"message": "Password updated successfully"}, 
                status=status.HTTP_200_OK
            )
            
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProfilePhotoUploadView(APIView):
    """
    API View to upload profile photo (placeholder for future implementation)
    """
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        """
        Upload user profile photo
        Note: This is a placeholder. You'll need to add model field and storage logic.
        """
        # For now, just return a success message
        return Response(
            {"message": "Profile photo upload endpoint. Implementation pending."},
            status=status.HTTP_200_OK
        )

class ExtendedTokenRefreshView(TokenRefreshView):
    """
    Custom token refresh view that provides consistent token format
    and detailed error handling for debugging.
    """
    serializer_class = TokenRefreshSerializer
    
    def post(self, request, *args, **kwargs):
        try:
            # Get the standard response from parent class
            response = super().post(request, *args, **kwargs)
            
            # Ensure consistent token format in response
            if response.status_code == 200:
                data = response.data
                # Normalize token keys for frontend consistency
                normalized_data = {
                    'access': data.get('access'),
                    'access_token': data.get('access'),  # For backward compatibility
                }
                # Include refresh token if provided
                if 'refresh' in data:
                    normalized_data['refresh'] = data['refresh']
                    normalized_data['refresh_token'] = data['refresh']
                
                return Response(normalized_data, status=status.HTTP_200_OK)
            
            return response
            
        except Exception as e:
            print(f"Token refresh error: {str(e)}")
            return Response(
                {
                    "error": "Invalid or expired refresh token",
                    "detail": str(e),
                    "code": "token_not_valid"
                },
                status=status.HTTP_401_UNAUTHORIZED
            )


#savings section
class GoalCategoryViewSet(viewsets.ModelViewSet):
    """ViewSet for managing goal categories"""
    serializer_class = GoalCategorySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Return default categories and user's custom categories"""
        return GoalCategory.objects.filter(
            # Either a default category or owned by the user
            models.Q(is_default=True) | models.Q(created_by=self.request.user)
        ).order_by('name')
class SavingsGoalViewSet(viewsets.ModelViewSet):
    """ViewSet for SavingsGoal model"""
    serializer_class = SavingsGoalSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        """Return only goals belonging to the current user"""
        return SavingsGoal.objects.filter(user=self.request.user)
    
    def get_serializer_class(self):
        """Use different serializers based on action"""
        if self.action == 'list':
            return SavingsGoalSummarySerializer
        return self.serializer_class
    
    @action(detail=True, methods=['post'], url_path='mark-complete')
    def mark_complete(self, request, pk=None):
        """Mark a savings goal as completed"""
        goal = self.get_object()
        goal.is_completed = True
        goal.save()
        serializer = self.get_serializer(goal)
        return Response(serializer.data)
    
    def contributions(self, request, pk=None):
        """Get all contributions for a specific goal"""
        goal = self.get_object()
        contributions = goal.contributions.all()
        serializer = ContributionSerializer(contributions, many=True)
        return Response(serializer.data)
        
    @action(detail=True, methods=['post'], url_path='contributions')
    def add_contribution(self, request, pk=None):
        """Add a contribution to a goal"""
        goal = self.get_object()
        serializer = ContributionCreateSerializer(data=request.data, context={'request': request})
        if serializer.is_valid():
            serializer.save(savings_goal=goal)

            goal.refresh_from_db()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ContributionCreateAPIView(generics.CreateAPIView):
    """API view to create a contribution for a specific goal"""
    serializer_class = ContributionCreateSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_serializer_context(self):
        context = super().get_serializer_context()
        return context
    
    


class ContributionDetailAPIView(generics.RetrieveDestroyAPIView):
    """API view to retrieve or delete a specific contribution"""
    serializer_class = ContributionSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        goal_id = self.kwargs.get('goal_id')
        return Contribution.objects.filter(
            savings_goal_id=goal_id, 
            savings_goal__user=self.request.user
        )
        
    def patch(self, request, *args, **kwargs):
        """Update a specific contribution partially"""
        instance = self.get_object()
        
        # Check if this contribution belongs to the requesting user
        if instance.savings_goal.user != request.user:
            return Response(
                {"detail": "You do not have permission to update this contribution."},
                status=status.HTTP_403_FORBIDDEN
            )
        
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        
        # After saving, recalculate the goal's current amount
        goal = instance.savings_goal
        total = Contribution.objects.filter(savings_goal=goal).aggregate(
            total=Sum('amount')
        )['total'] or 0
        
        # Update goal's current amount and completed status
        goal.current_amount = total
        goal.is_completed = total >= goal.target_amount
        goal.save()
        
        return Response(serializer.data)

class GoalSummaryAPIView(generics.ListAPIView):
    """API view to get a summary of all savings goals"""
    serializer_class = SavingsGoalSummarySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return SavingsGoal.objects.filter(user=self.request.user)
    
    def list(self, request, *args, **kwargs):
        queryset = self.get_queryset()
        
        # Calculate summary statistics
        active_goals = queryset.filter(is_completed=False).count()
        completed_goals = queryset.filter(is_completed=True).count()
        total_saved = sum(goal.current_amount for goal in queryset)
        total_target = sum(goal.target_amount for goal in queryset)
        
        # Get the regular list
        serializer = self.get_serializer(queryset, many=True)
        
        return Response({
            'goals': serializer.data,
            'stats': {
                'active_goals': active_goals,
                'completed_goals': completed_goals,
                'total_saved': total_saved,
                'total_target': total_target,
                'overall_progress': int((total_saved / total_target * 100) if total_target > 0 else 0)
            }
        })
        
        




class CustomCategoryListCreateView(generics.ListCreateAPIView):
    serializer_class = CustomCategorySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return CustomCategory.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
        
        
# Personal Budget Views
class PersonalBudgetListCreateView(generics.ListCreateAPIView):
    serializer_class = PersonalBudgetSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return PersonalBudget.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class PersonalBudgetDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = PersonalBudgetSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return PersonalBudget.objects.filter(user=self.request.user)

class BudgetExpenseItemListCreateView(generics.ListCreateAPIView):
    serializer_class = BudgetExpenseItemSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        budget_id = self.kwargs.get('budget_id')
        return BudgetExpenseItem.objects.filter(
            budget_id=budget_id,
            budget__user=self.request.user
        )
    
    def perform_create(self, serializer):
        budget_id = self.kwargs.get('budget_id')
        budget = PersonalBudget.objects.get(id=budget_id, user=self.request.user)
        serializer.save(budget=budget)

class BudgetExpenseItemDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = BudgetExpenseItemSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return BudgetExpenseItem.objects.filter(budget__user=self.request.user)

class CustomCategoryListCreateView(generics.ListCreateAPIView):
    serializer_class = CustomCategorySerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return CustomCategory.objects.filter(user=self.request.user)
    
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def budget_rules_info(request):
    """Get information about available budget rules"""
    rules = {
        '50_30_20': {
            'name': '50/30/20 Rule',
            'description': 'A popular guideline for dividing your after-tax income',
            'allocations': {
                'needs': {
                    'percentage': 50,
                    'description': 'Essential expenses like rent, food, utilities, insurance',
                    'categories': ['housing', 'utilities', 'groceries', 'transportation', 'insurance', 'debt_payments', 'phone', 'healthcare', 'childcare']
                },
                'wants': {
                    'percentage': 30,
                    'description': 'Discretionary spending like entertainment, dining out, subscriptions',
                    'categories': ['dining_out', 'entertainment', 'shopping', 'personal_care', 'subscriptions', 'hobbies', 'travel', 'drinks', 'clothing']
                },
                'savings': {
                    'percentage': 20,
                    'description': 'Savings, investments, and retirement planning',
                    'categories': ['emergency_fund', 'general_savings', 'investments', 'retirement_401k', 'retirement_ira']
                }
            }
        },
        'balanced_life': {
            'name': 'Balanced Life Rule (50/10/10/30)',
            'description': 'A comprehensive approach balancing fixed costs, investments, savings, and guilt-free spending',
            'allocations': {
                'fixed_costs': {
                    'percentage_range': '50-60%',
                    'percentage': 55,
                    'description': 'Fixed expenses including rent/mortgage, utilities, debt payments',
                    'categories': ['housing', 'utilities', 'debt_payments', 'insurance', 'phone']
                },
                'investment': {
                    'percentage': 10,
                    'description': 'Long-term investments including 401k, IRA, and other investments',
                    'categories': ['investments', 'retirement_401k', 'retirement_ira']
                },
                'savings': {
                    'percentage_range': '5-10%',
                    'percentage': 7.5,
                    'description': 'Short to medium-term savings for specific goals',
                    'categories': ['emergency_fund', 'vacation_savings', 'house_down_payment', 'general_savings']
                },
                'guilt_free': {
                    'percentage_range': '20-35%',
                    'percentage': 27.5,
                    'description': 'Discretionary spending for enjoyment without guilt',
                    'categories': ['dining_out', 'drinks', 'clothing', 'entertainment', 'shopping', 'personal_care', 'subscriptions']
                }
            }
        },
        'custom': {
            'name': 'Custom Budget',
            'description': 'Create your own budget categories and allocations',
            'allocations': 'User-defined categories and amounts'
        }
    }
    
    return Response(rules)

@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def create_rule_based_budget(request):
    """Create a budget using a specific budgeting rule"""
    rule_type = request.data.get('budget_type')
    total_income = request.data.get('total_income', 0)
    
    if rule_type not in ['classic', 'flexible']:
        return Response(
            {'error': 'Invalid budget rule type'}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    
    # Get current EAT time for budget name
    eat_tz = get_eat_timezone()
    current_time = timezone.now().astimezone(eat_tz)
    month_year = current_time.strftime('%B %Y')
    
    # Create the budget
    budget_data = {
        'name': f"{rule_type.replace('_', '/').title()} Budget - {request.data.get('name', month_year)}",
        'budget_type': rule_type,
        'total_income': total_income,
        'budget_period_start': request.data.get('budget_period_start'),
        'budget_period_end': request.data.get('budget_period_end'),
    }
    
    serializer = PersonalBudgetSerializer(data=budget_data)
    if serializer.is_valid():
        budget = serializer.save(user=request.user)
        return Response(PersonalBudgetSerializer(budget).data, status=status.HTTP_201_CREATED)
    
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def current_datetime_eat(request):
    """Get current date and time in East Africa Time"""
    eat_tz = get_eat_timezone()
    current_time = timezone.now().astimezone(eat_tz)
    
    return Response({
        'current_datetime': current_time.isoformat(),
        'current_date': current_time.date().isoformat(),
        'current_time': current_time.time().isoformat(),
        'timezone': 'Africa/Nairobi',
        'formatted_datetime': current_time.strftime('%Y-%m-%d %H:%M:%S'),
        'formatted_date': current_time.strftime('%Y-%m-%d'),
        'month_year': current_time.strftime('%B %Y')
    })

    

class DebtListCreateView(generics.ListCreateAPIView):
    serializer_class = DebtSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Debt.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)


class DebtDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = DebtSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Debt.objects.filter(user=self.request.user)


class DebtRepaymentStrategyView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def get(self, request):
        print("\n=== DebtRepaymentStrategyView CALLED ===")
        print(f"User ID: {request.user.id}")
        print(f"User Email: {request.user.email}") 
        print(f"Timestamp: {timezone.now()}")
        
        strategy = request.query_params.get('strategy', 'avalanche')
        print(f"Strategy requested: {strategy}")
        
        try:
            # Get active debts for this user
            debts = Debt.objects.filter(user=request.user, status='active')
            print(f"Found {debts.count()} active debts")
            
            if not debts.exists():
                print("No active debts found, returning 404")
                return Response({'error': 'No active debts found.'}, status=status.HTTP_404_NOT_FOUND)
            
            # Serialize the debts
            serializer = DebtSerializer(debts, many=True)
            debts_data = serializer.data
            
            # Debug debt data
            print(f"Processing {len(debts_data)} debts")
            for i, debt in enumerate(debts_data):
                print(f"Debt {i+1}: {debt['name']}, Balance: {debt['remaining_balance']}, Rate: {debt['interest_rate']}%")
            
            # Convert string values to Decimal
            for d in debts_data:
                d['remaining_balance'] = Decimal(str(d['remaining_balance']))
                d['monthly_min_payment'] = Decimal(str(d['monthly_min_payment']))
                d['interest_rate'] = Decimal(str(d['interest_rate']))
                # Make sure these fields exist in each debt object
                d['extra_monthly_payment'] = Decimal(str(d.get('extra_monthly_payment', 0)))
                d['extra_yearly_payment'] = Decimal(str(d.get('extra_yearly_payment', 0)))
            
            # Calculate extra payments from the serialized data, not the model objects
            extra_monthly = sum(Decimal(str(d.get('extra_monthly_payment', 0))) for d in debts_data)
            extra_yearly = sum(Decimal(str(d.get('extra_yearly_payment', 0))) for d in debts_data)
            
            print(f"Extra monthly payment: {extra_monthly}, Extra yearly payment: {extra_yearly}")
            print(f"Starting calculation with strategy: {strategy}")
            
            # Track calculation time
            start_time = time.time()
            results = calculate_repayment_schedule(debts_data, extra_monthly, extra_yearly, strategy)
            end_time = time.time()
            
            print(f"Calculation completed in {end_time - start_time:.2f} seconds")
            print(f"Results - Months to payoff: {results['months_to_payoff']}, Interest paid: {results['total_interest_paid']}")
            
            return Response(results, status=status.HTTP_200_OK)
        except Exception as e:
            print(f"Error in repayment calculation: {str(e)}")
            import traceback
            traceback.print_exc()
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class DeleteDebtsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request):
        Debt.objects.filter(user=request.user).delete()
        return Response({'message': 'All debts deleted.'}, status=status.HTTP_204_NO_CONTENT)
    
# Budget Expense Item Views
class BudgetExpenseItemListCreateView(generics.ListCreateAPIView):
    serializer_class = BudgetExpenseItemSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        budget_id = self.kwargs.get('budget_id')
        return BudgetExpenseItem.objects.filter(
            budget_id=budget_id,
            budget__user=self.request.user
        )
    
    def perform_create(self, serializer):
        budget_id = self.kwargs.get('budget_id')
        budget = PersonalBudget.objects.get(id=budget_id, user=self.request.user)
        serializer.save(budget=budget)

class BudgetExpenseItemDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = BudgetExpenseItemSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_queryset(self):
        return BudgetExpenseItem.objects.filter(budget__user=self.request.user)

    
class DebtDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = DebtSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return Debt.objects.filter(user=self.request.user)

class DeleteDebtsView(APIView):
    permission_classes = [permissions.IsAuthenticated]

    def delete(self, request):
        confirm = request.query_params.get('confirm', 'false').lower()
        debt_ids = request.data.get('debt_ids', None)

        if confirm != 'true':
            return Response(
                {"error": "Deletion not confirmed. Add ?confirm=true to proceed."},
                status=status.HTTP_400_BAD_REQUEST
            )

        queryset = Debt.objects.filter(user=request.user)

        if debt_ids:
            queryset = queryset.filter(id__in=debt_ids)

        deleted_count = queryset.count()
        queryset.delete()

        return Response(
            {"message": f"{deleted_count} debt(s) deleted successfully."},
            status=status.HTTP_204_NO_CONTENT
        )
    
# Additional API Views for specific actions
@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
def mark_expense_as_paid(request, expense_id):
    """Mark an expense as paid with optional actual amount"""
    try:
        expense = BudgetExpenseItem.objects.get(
            id=expense_id, 
            budget__user=request.user
        )
        
        amount = request.data.get('amount')
        payment_date = request.data.get('payment_date')
        
        expense.mark_as_paid(amount=amount, payment_date=payment_date)
        
        serializer = BudgetExpenseItemSerializer(expense)
        return Response(serializer.data)
    
    except BudgetExpenseItem.DoesNotExist:
        return Response({'error': 'Expense not found'}, status=404)

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def budget_summary(request, budget_id):
    """Get detailed budget summary with analytics"""
    try:
        budget = PersonalBudget.objects.get(id=budget_id, user=request.user)
        
        # Get overdue expenses
        overdue_expenses = budget.expense_items.filter(
            due_date__lt=timezone.now().date(),
            is_paid=False
        )
        
        # Get upcoming expenses (next 7 days)
        upcoming_expenses = budget.expense_items.filter(
            due_date__gte=timezone.now().date(),
            due_date__lte=timezone.now().date() + timezone.timedelta(days=7),
            is_paid=False
        )
        
        summary = {
            'budget': PersonalBudgetSerializer(budget).data,
            'overdue_expenses': BudgetExpenseItemSerializer(overdue_expenses, many=True).data,
            'upcoming_expenses': BudgetExpenseItemSerializer(upcoming_expenses, many=True).data,
            'total_overdue_amount': sum(exp.planned_expense for exp in overdue_expenses),
            'total_upcoming_amount': sum(exp.planned_expense for exp in upcoming_expenses),
        }
        
        return Response(summary)
    
    except PersonalBudget.DoesNotExist:
        return Response({'error': 'Budget not found'}, status=404)

@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def user_budget_analytics(request):
    """Get user's overall budget analytics across all budgets"""
    user_budgets = PersonalBudget.objects.filter(user=request.user, is_active=True)
    
    total_income = sum(budget.total_income for budget in user_budgets)
    total_planned_expenses = sum(budget.total_planned_expenses for budget in user_budgets)
    total_actual_expenses = sum(budget.total_actual_expenses for budget in user_budgets)
    
    analytics = {
        'total_budgets': user_budgets.count(),
        'total_income': total_income,
        'total_planned_expenses': total_planned_expenses,
        'total_actual_expenses': total_actual_expenses,
        'overall_planned_variance': total_income - total_planned_expenses,
        'overall_actual_variance': total_income - total_actual_expenses,
        'average_budget_utilization': (total_planned_expenses / total_income * 100) if total_income > 0 else 0,
    }
    
    return Response(analytics)

class BalanceSheetListCreateView(generics.ListCreateAPIView):
    serializer_class = BalanceSheetSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return BalanceSheet.objects.filter(user=self.request.user)

    def perform_create(self, serializer):
        serializer.save(user=self.request.user)

class BalanceSheetDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = BalanceSheetSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return BalanceSheet.objects.filter(user=self.request.user)
    
class BalanceSheetDetailView(RetrieveUpdateDestroyAPIView):
    queryset = BalanceSheet.objects.all()
    serializer_class = BalanceSheetSerializer

class InvestmentCalculationView(APIView):
    def post(self, request):
        serializer = InvestmentCalculationSerializer(data=request.data)
        if serializer.is_valid():
            result = investment_schedule(serializer.validated_data)
            return Response(result, status=status.HTTP_200_OK)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

class FinancialProjectionListCreateView(generics.ListCreateAPIView):
    serializer_class = FinancialProjectionSerializer
    permission_classes = [IsAuthenticated]  # Add this for security

    def get_queryset(self):
        # Filter by authenticated user
        return FinancialProjection.objects.filter(user=self.request.user)

    def get_serializer_context(self):
        return {'request': self.request}  # No projection calculation
   
    def perform_create(self, serializer):
        serializer.save(user=self.request.user)
   
class FinancialProjectionDetailView(generics.RetrieveUpdateDestroyAPIView):
    serializer_class = FinancialProjectionSerializer
    permission_classes = [IsAuthenticated]  # Add this for security

    def get_queryset(self):
        # Filter by authenticated user - ensures users can only access their own projections
        return FinancialProjection.objects.filter(user=self.request.user)

    def get_serializer_context(self):
        return {'request': self.request}  # No projection calculation

# Fix the duplicate class name issue
class FinancialProjectionCalculationView(generics.RetrieveAPIView):
    serializer_class = FinancialProjectionSerializer
    permission_classes = [IsAuthenticated]  # Add this for security

    def get_queryset(self):
        # Filter by authenticated user
        return FinancialProjection.objects.filter(user=self.request.user)

    def get_serializer_context(self):
        return {
            'request': self.request,
            'include_projection': True
        }

# Separate view for projection calculations only
class FinancialProjectionResultView(APIView):
    permission_classes = [IsAuthenticated]  # Add this for security
    
    def get(self, request, pk):
        # Get projection and ensure it belongs to the authenticated user
        projection = get_object_or_404(
            FinancialProjection, 
            pk=pk, 
            user=request.user  # This is crucial - filter by user
        )
        result = run_scenarios(projection)
        serializer = WellnessProjectionSerializer(result)
        return Response(serializer.data)
    
