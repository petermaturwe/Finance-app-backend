from .models import *
from rest_framework import serializers
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.contrib.auth import authenticate
from django.utils.encoding import  force_str, smart_bytes
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.contrib.sites.shortcuts import get_current_site
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from .utils import send_normal_email
from django.urls import reverse
from django.utils import timezone
from .utils import run_scenarios
from .utils import send_password_reset_otp_email

# from .utils import calculate_dynamic_projection
OTP_EXP_MINUTES =15
class UserRegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(max_length=68, min_length=6, write_only=True)
    password2= serializers.CharField(max_length=68, min_length=6, write_only=True)

    class Meta:
        model=User
        fields = ['email', 'first_name', 'last_name', 'phone_number','password', 'password2']

    def validate(self, attrs):
        password=attrs.get('password', '')
        password2 =attrs.get('password2', '')
        if password !=password2:
            raise serializers.ValidationError("passwords do not match")
         
        return attrs

    def create(self, validated_data):
        user= User.objects.create_user(
            email=validated_data['email'],
            first_name=validated_data.get('first_name'),
            last_name=validated_data.get('last_name'),
            phone_number=validated_data.get('phone_number'),
            password=validated_data.get('password')
            )
        return user

class LoginSerializer(serializers.ModelSerializer):
    email = serializers.EmailField(max_length=155, min_length=6)
    password = serializers.CharField(max_length=68, write_only=True)
    full_name = serializers.CharField(max_length=255, read_only=True)
    first_name = serializers.CharField(max_length=255, read_only=True)  # ADD THIS
    last_name = serializers.CharField(max_length=255, read_only=True)   # ADD THIS
    access_token = serializers.CharField(max_length=255, read_only=True)
    refresh_token = serializers.CharField(max_length=255, read_only=True)

    class Meta:
        model = User
        fields = ['email', 'password', 'full_name', 'first_name', 'last_name', 'access_token', 'refresh_token']

    def validate(self, attrs):
        email = attrs.get('email')
        password = attrs.get('password')
        request = self.context.get('request')
        user = authenticate(request, email=email, password=password)
        if not user:
            raise AuthenticationFailed("invalid credential try again")
        if not user.is_verified:
            raise AuthenticationFailed("Email is not verified")
        tokens = user.tokens()
        return {
            'email': user.email,
            'full_name': user.get_full_name,
            'first_name': user.first_name,        # ADD THIS
            'last_name': user.last_name,          # ADD THIS
            "access_token": str(tokens.get('access')),
            "refresh_token": str(tokens.get('refresh'))
        }

class CheckEmailSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

class PasswordResetRequestSerializer(serializers.Serializer):
    email = serializers.EmailField(max_length=255)

    class Meta:
        fields = ['email']

    def validate(self, attrs):
        email = attrs.get('email')
        request = self.context.get('request')

        # Always respond success, only send if user exists (avoid enumeration)
        if User.objects.filter(email=email).exists():
            send_password_reset_otp_email(email, request)
        return attrs


class VerifyOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(min_length=4, max_length=8)

    class Meta:
        fields = ['email', 'otp']

    def validate(self, attrs):
        email = attrs.get('email')
        otp = str(attrs.get('otp')).strip()

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({'otp': 'Invalid or expired code'})

        now = timezone.now()
        qs = OneTimePassword.objects.filter(
            user=user,
            otp=otp,
            is_used=False,
            purpose=OneTimePassword.Purpose.PASSWORD_RESET,
            created_at__gte=now - timedelta(minutes=OTP_EXP_MINUTES),
        )
        if not qs.exists():
            raise serializers.ValidationError({'otp': 'Invalid or expired code'})

        attrs['user'] = user
        attrs['_otp_queryset'] = qs
        return attrs


class SetNewPasswordOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp = serializers.CharField(min_length=4, max_length=8)
    password = serializers.CharField(max_length=100, min_length=8, write_only=True)
    confirm_password = serializers.CharField(max_length=100, min_length=8, write_only=True)

    class Meta:
        fields = ['email', 'otp', 'password', 'confirm_password']

    def validate(self, attrs):
        email = attrs.get('email')
        otp = str(attrs.get('otp')).strip()
        password = attrs.get('password')
        confirm_password = attrs.get('confirm_password')

        if password != confirm_password:
            raise serializers.ValidationError({'confirm_password': 'Passwords do not match'})

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            raise serializers.ValidationError({'otp': 'Invalid or expired code'})

        now = timezone.now()
        qs = OneTimePassword.objects.filter(
            user=user,
            otp=otp,
            is_used=False,
            purpose=OneTimePassword.Purpose.PASSWORD_RESET,
            created_at__gte=now - timedelta(minutes=OTP_EXP_MINUTES),
        )
        if not qs.exists():
            raise serializers.ValidationError({'otp': 'Invalid or expired code'})

        attrs['user'] = user
        attrs['_otp_queryset'] = qs
        return attrs

    def save(self, **kwargs):
        user = self.validated_data['user']
        qs = self.validated_data['_otp_queryset']
        password = self.validated_data['password']

        user.set_password(password)
        user.save()

        # Mark matched OTP(s) as used
        qs.update(is_used=True)
        return user
    
class LogoutUserSerializer(serializers.Serializer):
    refresh_token=serializers.CharField()

    default_error_message = {
        'bad_token': ('Token is expired or invalid')
    }

    def validate(self, attrs):
        self.token = attrs.get('refresh_token')

        return attrs

    def save(self, **kwargs):
        try:
            token=RefreshToken(self.token)
            token.blacklist()
        except TokenError:
            return self.fail('bad_token')
        


class UserProfileSerializer(serializers.ModelSerializer):
    """Serializer for user profile data"""
    full_name = serializers.SerializerMethodField()
    
    class Meta:
        model = User
        fields = ['id', 'email', 'first_name', 'last_name', 'phone_number', 'full_name']
        read_only_fields = ['email']
    
    def get_full_name(self, obj):
        return f"{obj.first_name} {obj.last_name}".strip()


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user profile data"""
    
    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'phone_number']
        
    def validate(self, attrs):
        """Validate the profile update data"""
        # You can add custom validation logic here if needed
        return attrs


class ChangePasswordSerializer(serializers.Serializer):
    """
    Serializer for password change endpoint
    """
    current_password = serializers.CharField(required=True)
    new_password = serializers.CharField(required=True, min_length=6)
    confirm_password = serializers.CharField(required=True, min_length=6)
    
    def validate(self, attrs):
        """
        Validate that the new passwords match
        """
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"error": "New passwords do not match."})
        
        return attrs


#savings serializers
class GoalCategorySerializer(serializers.ModelSerializer):
    """Serializer for GoalCategory model"""
    
    class Meta:
        model = GoalCategory
        fields = ['id', 'name','is_default', 'created_at']
        read_only_fields = ['id', 'is_default', 'created_at']
    
    def create(self, validated_data):
        """Create a category associated with the current user if not a default one"""
        user = self.context['request'].user
        validated_data['created_by'] = user
        return super().create(validated_data)


class ContributionSerializer(serializers.ModelSerializer):
    """Serializer for Contribution model"""
    
    class Meta:
        model = Contribution
        fields = ['id', 'amount', 'notes', 'contribution_date', 'created_at']
        read_only_fields = ['id', 'created_at']



class SavingsGoalSerializer(serializers.ModelSerializer):
    """Serializer for SavingsGoal model"""
    
    progress_percentage = serializers.IntegerField(read_only=True)
    days_remaining = serializers.IntegerField(read_only=True)
    status = serializers.CharField(read_only=True)
    contributions = ContributionSerializer(many=True, read_only=True)
    category_name = serializers.CharField(source='category.name', read_only=True)
    
    class Meta:
        model = SavingsGoal
        fields = [
            'id', 'name', 'description', 'target_amount', 'current_amount',
            'deadline', 'is_completed', 'category', 'category_name', 'created_at', 'updated_at',
            'progress_percentage', 'days_remaining', 'status', 'contributions'
        ]
        read_only_fields = ['id', 'current_amount', 'created_at', 'updated_at', 'category_name']
    
    def validate_deadline(self, value):
        """Validate that deadline is not in the past"""
        if value < timezone.now().date():
            raise serializers.ValidationError("Deadline cannot be in the past")
        return value
    
    def create(self, validated_data):
        """Create a new savings goal associated with the current user"""
        user = self.context['request'].user
        validated_data['user'] = user
        
        # If a category name was provided but not an ID, create or get the category
        category_data = self.context['request'].data.get('category_name')
        if category_data and not validated_data.get('category'):
            category, created = GoalCategory.objects.get_or_create(
                name=category_data,
                defaults={'created_by': user}
            )
            validated_data['category'] = category
            
        return super().create(validated_data)


class ContributionCreateSerializer(serializers.ModelSerializer):
    """Serializer for creating contributions"""
    
    class Meta:
        model = Contribution
        fields = ['id', 'amount', 'notes', 'contribution_date']
        read_only_fields = ['id']

class SavingsGoalSummarySerializer(serializers.ModelSerializer):
    """Simplified serializer for dashboard/list views"""
    
    progress_percentage = serializers.IntegerField(read_only=True)
    days_remaining = serializers.IntegerField(read_only=True)
    status = serializers.CharField(read_only=True)
    category_name = serializers.CharField(source='category.name', read_only=True)
    
    class Meta:
        model = SavingsGoal
        fields = [
            'id', 'name', 'target_amount', 'current_amount',
            'deadline', 'progress_percentage', 'days_remaining',
            'status', 'category', 'category_name'
        ]
        



#New Code
class BudgetExpenseItemSerializer(serializers.ModelSerializer):
    id = serializers.IntegerField(required=False)
    variance = serializers.SerializerMethodField()
    variance_percentage = serializers.SerializerMethodField()
    is_over_budget = serializers.SerializerMethodField()
    category_name = serializers.SerializerMethodField()
    rule_category = serializers.SerializerMethodField()
    days_until_due = serializers.SerializerMethodField()
    is_overdue = serializers.SerializerMethodField()
    
    class Meta:
        model = BudgetExpenseItem
        fields = [
            'id', 'category', 'custom_category', 'item_name', 'planned_expense', 
            'actual_expense', 'priority', 'expense_type', 'due_date', 'is_paid', 
            'payment_date', 'notes', 'variance', 'variance_percentage', 
            'is_over_budget', 'category_name', 'rule_category', 'days_until_due', 'is_overdue'
        ]
    
    def get_variance(self, obj):
        return obj.variance
    
    def get_variance_percentage(self, obj):
        return obj.variance_percentage
    
    def get_is_over_budget(self, obj):
        return obj.is_over_budget
    
    def get_category_name(self, obj):
        return obj.get_category_name
    
    def get_rule_category(self, obj):
        return obj.rule_category
    
    def get_days_until_due(self, obj):
        return obj.days_until_due
    
    def get_is_overdue(self, obj):
        return obj.is_overdue

class PersonalBudgetSerializer(serializers.ModelSerializer):
    expense_items = BudgetExpenseItemSerializer(many=True, required=False)
    total_planned_expenses = serializers.SerializerMethodField()
    total_actual_expenses = serializers.SerializerMethodField()
    planned_budget_variance = serializers.SerializerMethodField()
    actual_budget_variance = serializers.SerializerMethodField()
    budget_utilization_percentage = serializers.SerializerMethodField()
    actual_utilization_percentage = serializers.SerializerMethodField()
    is_over_budget = serializers.SerializerMethodField()
    expenses_by_category = serializers.SerializerMethodField()
    expenses_by_priority = serializers.SerializerMethodField()
    rule_based_summary = serializers.SerializerMethodField()
    
    class Meta:
        model = PersonalBudget
        fields = [
            'id', 'name', 'budget_type', 'budget_period_start', 'budget_period_end', 
            'total_income', 'needs_allocation', 'wants_allocation', 'savings_allocation',
            'fixed_costs_allocation', 'investment_allocation', 'guilt_free_allocation',
            'is_active', 'created_at', 'updated_at', 'expense_items',
            'total_planned_expenses', 'total_actual_expenses', 'planned_budget_variance',
            'actual_budget_variance', 'budget_utilization_percentage', 
            'actual_utilization_percentage', 'is_over_budget', 'expenses_by_category',
            'expenses_by_priority', 'rule_based_summary'
        ]
    
    def get_total_planned_expenses(self, obj):
        return obj.total_planned_expenses
    
    def get_total_actual_expenses(self, obj):
        return obj.total_actual_expenses
    
    def get_planned_budget_variance(self, obj):
        return obj.planned_budget_variance
    
    def get_actual_budget_variance(self, obj):
        return obj.actual_budget_variance
    
    def get_budget_utilization_percentage(self, obj):
        return obj.budget_utilization_percentage
    
    def get_actual_utilization_percentage(self, obj):
        return obj.actual_utilization_percentage
    
    def get_is_over_budget(self, obj):
        return obj.is_over_budget
    
    def get_expenses_by_category(self, obj):
        return list(obj.expenses_by_category)
    
    def get_expenses_by_priority(self, obj):
        return list(obj.expenses_by_priority)
    
    def get_rule_based_summary(self, obj):
        return obj.rule_based_summary
    
    def create(self, validated_data):
        expense_items_data = validated_data.pop('expense_items', [])
        budget = PersonalBudget.objects.create(**validated_data)
        
        for item_data in expense_items_data:
            BudgetExpenseItem.objects.create(budget=budget, **item_data)
        
        return budget
    
    def update(self, instance, validated_data):
        # Update top-level budget fields
        for field in ['name', 'budget_type', 'budget_period_start', 'budget_period_end', 'total_income', 'is_active', 'needs_allocation', 'wants_allocation', 'savings_allocation', 'giving_allocation']:
            if field in validated_data:
                setattr(instance, field, validated_data[field])
        instance.save()
        
        # Handle BudgetExpenseItem updates if 'expense_items' is included
        expense_items_data = validated_data.get('expense_items', None)
        if expense_items_data is not None:
            existing_item_ids = [item.id for item in instance.expense_items.all()]
            new_item_ids = []
            
            for item_data in expense_items_data:
                item_id = item_data.get('id', None)
                if item_id:
                    try:
                        item_instance = BudgetExpenseItem.objects.get(id=item_id, budget=instance)
                        for attr, value in item_data.items():
                            if attr != 'id':
                                setattr(item_instance, attr, value)
                        item_instance.save()
                        new_item_ids.append(item_id)
                    except BudgetExpenseItem.DoesNotExist:
                        continue  # skip invalid ID or foreign budget item
                else:
                    new_item = BudgetExpenseItem.objects.create(budget=instance, **item_data)
                    new_item_ids.append(new_item.id)
            
            # Optionally delete items not included in update (sync behavior)
            for item in instance.expense_items.exclude(id__in=new_item_ids):
                item.delete()
        
        return instance

class CustomCategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = CustomCategory
        fields = ['id', 'name', 'description']

    

class DebtSerializer(serializers.ModelSerializer):
    class Meta:
        model = Debt
        fields = [
            'id',
            'name',
            'remaining_balance',
            'monthly_min_payment',
            'interest_rate',
            'strategy',
            'extra_monthly_payment',
            'extra_yearly_payment',
            'status',  # Add this field
        ]


class BalanceSheetSerializer(serializers.ModelSerializer):
    total_assets = serializers.ReadOnlyField()
    total_liabilities = serializers.ReadOnlyField()
    net_worth = serializers.ReadOnlyField()

    class Meta:
        model = BalanceSheet
        fields = [
            'id',
            'own_house', 'household_contents', 'personal_cars', 'other_personal_assets',
            'current_account', 'savings_account', 'cash_at_hand',
            'wealth_mgt_fund', 'stocks_shares', 'money_market_funds', 'unit_linked_investments', 'cash_value_policies',
            'real_estate', 'business_value', 'sacco_shares', 'retirement_plans', 'other_investments',
            'personal_loans', 'overdraft_balances', 'sacco_loans', 'car_loans',
            'mortgages', 'creditors', 'credit_cards', 'other_liabilities',
            'total_assets', 'total_liabilities', 'net_worth', 'created_at'
        ]


class InvestmentCalculationSerializer(serializers.Serializer):
    starting_amount = serializers.FloatField()
    return_rate = serializers.FloatField()
    additional_contribution = serializers.FloatField()
    years = serializers.IntegerField()
    compound = serializers.ChoiceField(choices=['annually', 'monthly'])
    contribute_at = serializers.ChoiceField(choices=['beginning', 'end'])
    schedule_type = serializers.ChoiceField(choices=['annual', 'monthly'])  # this controls the output view


#Financial Wellness

class FinancialProjectionSerializer(serializers.ModelSerializer):
    wellness_projection = serializers.SerializerMethodField()

    class Meta:
        model = FinancialProjection
        fields = [
             "id", "title", "initial_capital",
             "savings_range", "roi_range",
             "expense_range", "inflation_range",
             "created_at", "wellness_projection"
         ]

    def get_wellness_projection(self, obj):
        # Only compute if context flag is set
        if self.context.get('include_projection'):
            from .utils import run_scenarios
            return run_scenarios(obj)
        return None
   
class ProjectionResultSerializer(serializers.Serializer):
    year = serializers.IntegerField(allow_null=True)
    savings_total = serializers.FloatField()
    savings_income = serializers.FloatField()


class WellnessProjectionSerializer(serializers.Serializer):
    fastest_path = ProjectionResultSerializer()
    slowest_path = ProjectionResultSerializer()
    average_path = ProjectionResultSerializer()


    
