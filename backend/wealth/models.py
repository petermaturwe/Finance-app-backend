from django.db import models
from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.utils.translation import gettext_lazy as _
from rest_framework_simplejwt.tokens import RefreshToken
from wealth.managers import UserManager
from django.utils.translation import gettext_lazy as _
from django.core.validators import MinValueValidator
from django.utils import timezone
import datetime
from decimal import Decimal
from django.core.validators import MinValueValidator
from django.db.models import JSONField, Q
import pytz
from django.contrib.postgres.fields import ArrayField
# Create your models here.


AUTH_PROVIDERS = {'email': 'email', 'google': 'google',
                  'github': 'github', 'linkedin': 'linkedin'}


class User(AbstractBaseUser, PermissionsMixin):
    id = models.BigAutoField(primary_key=True, editable=False)
    email = models.EmailField(
        max_length=255, verbose_name=_("Email Address"), unique=True
    )
    first_name = models.CharField(max_length=100, verbose_name=_("First Name"))
    last_name = models.CharField(max_length=100, verbose_name=_("Last Name"))
    phone_number = models.CharField(max_length=15, verbose_name=_("Phone Number"), blank=True, null=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    is_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    date_joined = models.DateTimeField(auto_now_add=True)
    last_login = models.DateTimeField(auto_now=True)
    auth_provider = models.CharField(
        max_length=50, blank=False, null=False, default=AUTH_PROVIDERS.get('email'))

    USERNAME_FIELD = "email"

    REQUIRED_FIELDS = ["first_name", "last_name"]

    objects = UserManager()

    def tokens(self):
        refresh = RefreshToken.for_user(self)
        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        }

    def __str__(self):
        return self.email

    @property
    def get_full_name(self):
        return f"{self.first_name.title()} {self.last_name.title()}"

class OneTimePassword(models.Model):
    class Purpose(models.TextChoices):
        EMAIL_VERIFY = "email_verify", _("Email Verification")
        PASSWORD_RESET = "password_reset", _("Password Reset")

    user = models.ForeignKey('wealth.User', on_delete=models.CASCADE, related_name='otps')
    otp = models.CharField(max_length=6)
    
    purpose = models.CharField(
        max_length=32,
        choices=Purpose.choices,
        default=Purpose.EMAIL_VERIFY,  # Default to email verification
    )

    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True, null=True, blank=True, db_index=True)

    class Meta:
        indexes = [
            models.Index(fields=['user', 'purpose', 'is_used']),
            models.Index(fields=['created_at']),
        ]
        constraints = [
            models.UniqueConstraint(
                fields=['user', 'purpose'],
                condition=Q(is_used=False),
                name='uniq_active_otp_per_user_purpose',
            )
        ]

    def __str__(self) -> str:
        return f"{getattr(self.user, 'first_name', self.user_id)} - {self.purpose} code"
    
#savings model
class GoalCategory(models.Model):
    """Model for storing goal categories"""
    name = models.CharField(_("Category Name"), max_length=100)
    is_default = models.BooleanField(_("Is Default"), default=False)
    created_by = models.ForeignKey('wealth.User', on_delete=models.SET_NULL, null=True, blank=True, related_name="created_categories")
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        verbose_name = _("Goal Category")
        verbose_name_plural = _("Goal Categories")
        ordering = ['name']
        constraints = [
          
            models.UniqueConstraint(
                fields=['name', 'created_by'], 
                name='unique_category_per_user'
            )
        ]
    
    def __str__(self):
        if self.is_default:
            return f"{self.name} (Default)"
        return self.name


class SavingsGoal(models.Model):
    """Model to track savings goals"""
    
    user = models.ForeignKey('wealth.User', on_delete=models.CASCADE, related_name='savings_goals')
    name = models.CharField(_("Goal Name"), max_length=255)
    description = models.TextField(_("Description"), blank=True, null=True)
    target_amount = models.DecimalField(
        _("Target Amount"), 
        max_digits=12, 
        decimal_places=2,
        validators=[MinValueValidator(1.0)]
    )
    
    current_amount = models.DecimalField(
        _("Current Amount"), 
        max_digits=12, 
        decimal_places=2,
        default=0.0
    )
    deadline = models.DateField(_("Goal Deadline"))
    is_completed = models.BooleanField(_("Is Completed"), default=False)
    category = models.ForeignKey(
        GoalCategory, 
        on_delete=models.SET_NULL, 
        related_name='goals',
        blank=True, 
        null=True,
        verbose_name=_("Category")
    )
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = _("Savings Goal")
        verbose_name_plural = _("Savings Goals")
    
    def __str__(self):
        return f"{self.name} (${self.target_amount})"
    
    @property
    def progress_percentage(self):
        if not self.target_amount:
            return 0
        if self.target_amount > 0:
            current = self.current_amount or 0
            return min(100, int((current / self.target_amount) * 100))
        return 0
    
    @property
    def days_remaining(self):
        if not self.deadline:
            return None
        today = timezone.now().date()
        if self.deadline > today:
            return (self.deadline - today).days
        return 0
    
    @property
    def status(self):
        if self.is_completed:
            return "COMPLETED"
        if self.current_amount and self.target_amount and self.current_amount >= self.target_amount:
            return "REACHED"
        if self.deadline and self.deadline < timezone.now().date():
            return "OVERDUE"
        return "ACTIVE"


class Contribution(models.Model):
    """Model to track contributions to savings goals"""
    
    savings_goal = models.ForeignKey(
        SavingsGoal, 
        on_delete=models.CASCADE, 
        related_name='contributions'
    )
    amount = models.DecimalField(
        _("Amount"), 
        max_digits=12, 
        decimal_places=2,
        validators=[MinValueValidator(0.01)]
    )
    notes = models.CharField(_("Notes"), max_length=255, blank=True, null=True)
    contribution_date = models.DateTimeField(default=timezone.now)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-contribution_date']
    
    def __str__(self):
        return f"${self.amount} for {self.savings_goal.name}"
    
    def save(self, *args, **kwargs):
        # Update the parent goal's current amount
        is_new = self.pk is None
        if is_new:
            self.savings_goal.current_amount += self.amount
            self.savings_goal.save()
        super().save(*args, **kwargs)
    
    def delete(self, *args, **kwargs):
        # Update the parent goal's current amount when a contribution is deleted
        self.savings_goal.current_amount -= self.amount
        self.savings_goal.save()
        super().delete(*args, **kwargs)
        


#New Code

# Helper functions for defaults that can be serialized
def get_first_day_of_current_month():
    """Return the first day of the current month"""
    # Using the current date provided: 2025-06-14
    current_date = datetime.datetime(2025, 6, 14).date()
    return current_date.replace(day=1)

def get_last_day_of_current_month():
    """Return the last day of the current month"""
    # Using the current date provided: 2025-06-14
    current_date = datetime.datetime(2025, 6, 14).date()
    # Get first day of current month
    first_day = current_date.replace(day=1)
    # Get first day of next month
    if first_day.month == 12:
        next_month = first_day.replace(year=first_day.year+1, month=1)
    else:
        next_month = first_day.replace(month=first_day.month+1)
    # Subtract one day to get last day of current month
    last_day = next_month - datetime.timedelta(days=1)
    return last_day

def get_eat_timezone():
    """Get East Africa Time timezone"""
    return pytz.timezone('Africa/Nairobi')

def get_current_date_eat():
    """Get current date in East Africa Time"""
    eat_tz = get_eat_timezone()
    return timezone.now().astimezone(eat_tz).date()

def get_first_day_of_current_month():
    """Get first day of current month in EAT"""
    today = get_current_date_eat()
    return today.replace(day=1)

def get_last_day_of_current_month():
    """Get last day of current month in EAT"""
    today = get_current_date_eat()
    if today.month == 12:
        return today.replace(year=today.year + 1, month=1, day=1) - datetime.timedelta(days=1)
    else:
        return today.replace(month=today.month + 1, day=1) - datetime.timedelta(days=1)

class PersonalBudget(models.Model):
    BUDGET_TYPE_CHOICES = [
        ('custom', 'Custom Budget'),
        ('classic', 'Classic Rule (50/30/20)'),  
        ('flexible', 'Flexible Rule (50/10/10/30)'), 
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    
    # Budget type and rule
    budget_type = models.CharField(
        max_length=20, 
        choices=BUDGET_TYPE_CHOICES, 
        default='custom',
        help_text="Type of budgeting rule to use"
    )
    
    name = models.CharField(
        max_length=100, 
        help_text="Budget name (e.g., 'Monthly Budget - June 2025')",
        default="Default Budget"
    )
    
    budget_period_start = models.DateField(default=get_first_day_of_current_month)
    budget_period_end = models.DateField(default=get_last_day_of_current_month)
    
    total_income = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        validators=[MinValueValidator(Decimal('0.00'))],
        help_text="Total income available for this budget period",
        default=Decimal('0.00')
    )
    
    # Rule-based allocations (calculated based on budget_type)
    fixed_costs_allocation = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        default=Decimal('0.00'),
        help_text="Amount allocated for fixed costs (rent, utilities, debt)"
    )
    
    investment_allocation = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        default=Decimal('0.00'),
        help_text="Amount allocated for investments (401k, IRA, etc.)"
    )
    
    savings_allocation = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        default=Decimal('0.00'),
        help_text="Amount allocated for savings (emergency, vacation, house down payment)"
    )
    
    guilt_free_allocation = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        default=Decimal('0.00'),
        help_text="Amount allocated for guilt-free spending (dining, entertainment, shopping)"
    )
    
    # Legacy fields for backward compatibility with 50/30/20 rule
    needs_allocation = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        default=Decimal('0.00'),
        help_text="Amount allocated for needs/living expenses (50/30/20 rule)"
    )
    
    wants_allocation = models.DecimalField(
        max_digits=12, 
        decimal_places=2, 
        default=Decimal('0.00'),
        help_text="Amount allocated for wants/discretionary spending (50/30/20 rule)"
    )
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True)

    class Meta:
        ordering = ['-budget_period_start']
        
    def __str__(self):
        return f"{self.name} ({self.budget_period_start} to {self.budget_period_end})"
    
    def save(self, *args, **kwargs):
        """Override save to calculate rule-based allocations"""
        if self.total_income > 0:
            if self.budget_type == '50_30_20':
                # Original 50/30/20 rule
                self.needs_allocation = self.total_income * Decimal('0.50')
                self.wants_allocation = self.total_income * Decimal('0.30')
                self.savings_allocation = self.total_income * Decimal('0.20')
                # Clear new rule fields
                self.fixed_costs_allocation = Decimal('0.00')
                self.investment_allocation = Decimal('0.00')
                self.guilt_free_allocation = Decimal('0.00')
            elif self.budget_type == 'balanced_life':
                # New Balanced Life rule (using mid-range percentages)
                self.fixed_costs_allocation = self.total_income * Decimal('0.55')  # 55% (mid-range of 50-60%)
                self.investment_allocation = self.total_income * Decimal('0.10')   # 10%
                self.savings_allocation = self.total_income * Decimal('0.075')    # 7.5% (mid-range of 5-10%)
                self.guilt_free_allocation = self.total_income * Decimal('0.275') # 27.5% (mid-range of 20-35%)
                # Clear 50/30/20 fields
                self.needs_allocation = Decimal('0.00')
                self.wants_allocation = Decimal('0.00')
            else:  # custom
                # For custom budgets, keep user-defined allocations
                pass
        
        super().save(*args, **kwargs)
    
    @property
    def total_planned_expenses(self):
        """Returns the sum of all planned expenses"""
        return self.expense_items.aggregate(models.Sum('planned_expense'))['planned_expense__sum'] or Decimal('0.00')
    
    @property
    def total_actual_expenses(self):
        """Returns the sum of all actual expenses where paid"""
        return self.expense_items.filter(is_paid=True).aggregate(
            models.Sum('actual_expense')
        )['actual_expense__sum'] or Decimal('0.00')
    
    @property
    def planned_budget_variance(self):
        """Returns the difference between income and planned expenses"""
        return self.total_income - self.total_planned_expenses
    
    @property
    def actual_budget_variance(self):
        """Returns the difference between income and actual expenses"""
        return self.total_income - self.total_actual_expenses
    
    @property
    def budget_utilization_percentage(self):
        """Returns the percentage of budget planned to be used"""
        if self.total_income > 0:
            return (self.total_planned_expenses / self.total_income) * 100
        return 0
    
    @property
    def actual_utilization_percentage(self):
        """Returns the percentage of budget actually used"""
        if self.total_income > 0:
            return (self.total_actual_expenses / self.total_income) * 100
        return 0
    
    @property
    def is_over_budget(self):
        """Returns True if planned expenses exceed income"""
        return self.total_planned_expenses > self.total_income
    
    @property
    def rule_based_summary(self):
        """Returns budget rule breakdown"""
        if self.budget_type == 'custom':
            return None
        
        if self.budget_type == '50_30_20':
            return {
                'rule_type': self.get_budget_type_display(),
                'allocations': {
                    'needs': {
                        'amount': self.needs_allocation,
                        'percentage': (self.needs_allocation / self.total_income * 100) if self.total_income > 0 else 0,
                        'spent': self.get_category_spending('needs'),
                        'remaining': self.needs_allocation - self.get_category_spending('needs')
                    },
                    'wants': {
                        'amount': self.wants_allocation,
                        'percentage': (self.wants_allocation / self.total_income * 100) if self.total_income > 0 else 0,
                        'spent': self.get_category_spending('wants'),
                        'remaining': self.wants_allocation - self.get_category_spending('wants')
                    },
                    'savings': {
                        'amount': self.savings_allocation,
                        'percentage': (self.savings_allocation / self.total_income * 100) if self.total_income > 0 else 0,
                        'spent': self.get_category_spending('savings'),
                        'remaining': self.savings_allocation - self.get_category_spending('savings')
                    }
                }
            }
        elif self.budget_type == 'balanced_life':
            return {
                'rule_type': self.get_budget_type_display(),
                'allocations': {
                    'fixed_costs': {
                        'amount': self.fixed_costs_allocation,
                        'percentage': (self.fixed_costs_allocation / self.total_income * 100) if self.total_income > 0 else 0,
                        'spent': self.get_category_spending('fixed_costs'),
                        'remaining': self.fixed_costs_allocation - self.get_category_spending('fixed_costs')
                    },
                    'investment': {
                        'amount': self.investment_allocation,
                        'percentage': (self.investment_allocation / self.total_income * 100) if self.total_income > 0 else 0,
                        'spent': self.get_category_spending('investment'),
                        'remaining': self.investment_allocation - self.get_category_spending('investment')
                    },
                    'savings': {
                        'amount': self.savings_allocation,
                        'percentage': (self.savings_allocation / self.total_income * 100) if self.total_income > 0 else 0,
                        'spent': self.get_category_spending('savings'),
                        'remaining': self.savings_allocation - self.get_category_spending('savings')
                    },
                    'guilt_free': {
                        'amount': self.guilt_free_allocation,
                        'percentage': (self.guilt_free_allocation / self.total_income * 100) if self.total_income > 0 else 0,
                        'spent': self.get_category_spending('guilt_free'),
                        'remaining': self.guilt_free_allocation - self.get_category_spending('guilt_free')
                    }
                }
            }
    
    def get_category_spending(self, rule_category):
        """Get total spending for a rule-based category"""
        if self.budget_type == '50_30_20':
            category_mapping = {
                'needs': ['housing', 'utilities', 'groceries', 'transportation', 'insurance', 'debt_payments', 'phone', 'healthcare', 'childcare'],
                'wants': ['dining_out', 'entertainment', 'shopping', 'personal_care', 'subscriptions', 'hobbies', 'travel'],
                'savings': ['emergency_fund', 'savings', 'investments']
            }
        elif self.budget_type == 'balanced_life':
            category_mapping = {
                'fixed_costs': ['housing', 'utilities', 'debt_payments', 'insurance', 'phone'],
                'investment': ['investments', 'retirement_401k', 'retirement_ira'],
                'savings': ['emergency_fund', 'vacation_savings', 'house_down_payment', 'general_savings'],
                'guilt_free': ['dining_out', 'entertainment', 'shopping', 'personal_care', 'subscriptions', 'drinks', 'clothing']
            }
        else:
            return Decimal('0.00')
        
        categories = category_mapping.get(rule_category, [])
        return self.expense_items.filter(
            category__in=categories, 
            is_paid=True
        ).aggregate(
            models.Sum('actual_expense')
        )['actual_expense__sum'] or Decimal('0.00')
    
    @property
    def expenses_by_category(self):
        """Returns expenses grouped by category"""
        categories = {}
        for expense in self.expense_items.all():
            category_name = expense.get_category_name
            if category_name not in categories:
                categories[category_name] = {
                    'planned': Decimal('0.00'),
                    'actual': Decimal('0.00'),
                    'count': 0
                }
            categories[category_name]['planned'] += expense.planned_expense
            if expense.actual_expense is not None:
                categories[category_name]['actual'] += expense.actual_expense
            categories[category_name]['count'] += 1
            
        return [
            {
                'category': category,
                'planned_amount': data['planned'],
                'actual_amount': data['actual'],
                'item_count': data['count'],
                'percentage': (data['planned'] / self.total_planned_expenses * 100) if self.total_planned_expenses > 0 else 0
            } for category, data in categories.items()
        ]
    
    @property
    def expenses_by_priority(self):
        """Returns expenses grouped by priority"""
        priorities = {
            'high': {'planned': Decimal('0.00'), 'actual': Decimal('0.00'), 'count': 0},
            'medium': {'planned': Decimal('0.00'), 'actual': Decimal('0.00'), 'count': 0},
            'low': {'planned': Decimal('0.00'), 'actual': Decimal('0.00'), 'count': 0},
        }
        
        for expense in self.expense_items.all():
            priority = expense.priority
            priorities[priority]['planned'] += expense.planned_expense
            if expense.actual_expense is not None:
                priorities[priority]['actual'] += expense.actual_expense
            priorities[priority]['count'] += 1
            
        return [
            {
                'priority': priority,
                'planned_amount': data['planned'],
                'actual_amount': data['actual'],
                'item_count': data['count'],
                'percentage': (data['planned'] / self.total_planned_expenses * 100) if self.total_planned_expenses > 0 else 0
            } for priority, data in priorities.items()
        ]

class CustomCategory(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=50)
    description = models.CharField(max_length=100, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name_plural = "Custom Categories"
        unique_together = ['user', 'name']
        ordering = ['name']

    def __str__(self):
        return f"{self.user.username} - {self.name}"

class BudgetExpenseItem(models.Model):
    CATEGORY_CHOICES = [
        # Fixed Costs (Balanced Life Rule)
        ('housing', 'Housing & Rent'),
        ('utilities', 'Utilities'),
        ('insurance', 'Insurance'),
        ('debt_payments', 'Debt Payments'),
        ('phone', 'Phone & Internet'),
        
        # Investment Categories (Balanced Life Rule)
        ('investments', 'General Investments'),
        ('retirement_401k', '401(k) Contributions'),
        ('retirement_ira', 'IRA Contributions'),
        
        # Savings Categories (Balanced Life Rule)
        ('emergency_fund', 'Emergency Fund'),
        ('vacation_savings', 'Vacation Savings'),
        ('house_down_payment', 'House Down Payment'),
        ('general_savings', 'General Savings'),
        
        # Guilt-Free Spending (Balanced Life Rule)
        ('dining_out', 'Dining Out'),
        ('drinks', 'Drinks & Alcohol'),
        ('clothing', 'Clothes & Shoes'),
        ('entertainment', 'Entertainment'),
        ('shopping', 'Shopping'),
        ('personal_care', 'Personal Care'),
        ('subscriptions', 'Subscriptions & Memberships'),
        
        # Additional categories for flexibility
        ('groceries', 'Groceries'),
        ('transportation', 'Transportation & Gas'),
        ('healthcare', 'Healthcare & Medical'),
        ('childcare', 'Childcare'),
        ('hobbies', 'Hobbies & Recreation'),
        ('travel', 'Travel'),
        ('gifts', 'Gifts'),
        ('donations', 'Charitable Donations'),
        ('home_maintenance', 'Home Maintenance'),
        ('education', 'Education & Learning'),
        ('pets', 'Pet Care'),
        ('other', 'Other Expenses'),
    ]

    PRIORITY_CHOICES = [
        ('high', 'High Priority'),
        ('medium', 'Medium Priority'),
        ('low', 'Low Priority'),
    ]

    EXPENSE_TYPE_CHOICES = [
        ('fixed', 'Fixed - Same amount each period'),
        ('variable', 'Variable - Amount changes'),
        ('periodic', 'Periodic - Not every period'),
    ]

    budget = models.ForeignKey(PersonalBudget, related_name='expense_items', on_delete=models.CASCADE)
    category = models.CharField(max_length=50, choices=CATEGORY_CHOICES, blank=True, null=True)
    custom_category = models.ForeignKey(CustomCategory, on_delete=models.SET_NULL, null=True, blank=True)
    item_name = models.CharField(max_length=100)
    planned_expense = models.DecimalField(
        max_digits=10, 
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.00'))]
    )
    actual_expense = models.DecimalField(
        max_digits=10, 
        decimal_places=2, 
        null=True, 
        blank=True,
        validators=[MinValueValidator(Decimal('0.00'))]
    )
    priority = models.CharField(max_length=20, choices=PRIORITY_CHOICES, default='medium')
    expense_type = models.CharField(max_length=20, choices=EXPENSE_TYPE_CHOICES, default='variable')
    due_date = models.DateField(null=True, blank=True, help_text="When this expense is due")
    is_paid = models.BooleanField(default=False)
    payment_date = models.DateField(null=True, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['priority', 'due_date', 'category']

    @property
    def get_category_name(self):
        """Returns the category name whether it's predefined or custom"""
        if self.custom_category:
            return self.custom_category.name
        return self.get_category_display() if self.category else 'Uncategorized'
    
    @property
    def rule_category(self):
        """Returns which budget rule category this expense belongs to"""
        if self.budget.budget_type == '50_30_20':
            needs_categories = ['housing', 'utilities', 'groceries', 'transportation', 'insurance', 'debt_payments', 'phone', 'healthcare', 'childcare']
            wants_categories = ['dining_out', 'entertainment', 'shopping', 'personal_care', 'subscriptions', 'hobbies', 'travel', 'drinks', 'clothing']
            savings_categories = ['emergency_fund', 'general_savings', 'investments', 'retirement_401k', 'retirement_ira']
            
            if self.category in needs_categories:
                return 'needs'
            elif self.category in wants_categories:
                return 'wants'
            elif self.category in savings_categories:
                return 'savings'
            else:
                return 'other'
        elif self.budget.budget_type == 'balanced_life':
            fixed_costs_categories = ['housing', 'utilities', 'debt_payments', 'insurance', 'phone']
            investment_categories = ['investments', 'retirement_401k', 'retirement_ira']
            savings_categories = ['emergency_fund', 'vacation_savings', 'house_down_payment', 'general_savings']
            guilt_free_categories = ['dining_out', 'drinks', 'clothing', 'entertainment', 'shopping', 'personal_care', 'subscriptions']
            
            if self.category in fixed_costs_categories:
                return 'fixed_costs'
            elif self.category in investment_categories:
                return 'investment'
            elif self.category in savings_categories:
                return 'savings'
            elif self.category in guilt_free_categories:
                return 'guilt_free'
            else:
                return 'other'
        else:
            return 'custom'

    @property
    def variance(self):
        if self.actual_expense is None:
            return None
        return self.planned_expense - self.actual_expense
        
    @property
    def variance_percentage(self):
        if self.actual_expense is None or self.planned_expense == 0:
            return None
        return (self.variance / self.planned_expense) * 100

    @property
    def is_over_budget(self):
        if self.actual_expense is None:
            return False
        return self.actual_expense > self.planned_expense
        
    @property
    def days_until_due(self):
        if not self.due_date:
            return None
        today = get_current_date_eat()
        days = (self.due_date - today).days
        return max(0, days)
        
    @property
    def is_overdue(self):
        if not self.due_date or self.is_paid:
            return False
        today = get_current_date_eat()
        return self.due_date < today
        
    def mark_as_paid(self, amount=None, payment_date=None):
        """Mark this expense as paid with optional actual amount"""
        self.is_paid = True
        
        if amount is not None:
            self.actual_expense = Decimal(str(amount))
        elif self.actual_expense is None:
            self.actual_expense = self.planned_expense
            
        if payment_date is not None:
            if isinstance(payment_date, str):
                self.payment_date = datetime.datetime.strptime(payment_date, '%Y-%m-%d').date()
            else:
                self.payment_date = payment_date
        else:
            self.payment_date = get_current_date_eat()
            
        self.save()

    def __str__(self):
        return f"{self.item_name} - {self.get_category_display()}"
    
    
class Debt(models.Model):
    STRATEGY_CHOICES = [
        ('avalanche', 'Avalanche'),
        ('snowball', 'Snowball'),
        ('consolidation', 'Consolidation'),
    ]

    STATUS_CHOICES = [
        ('active', 'Active'),
        ('paid', 'Paid'),
        ('paused', 'Paused'),
        ('deferred', 'Deferred'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=100)
    remaining_balance = models.DecimalField(max_digits=10, decimal_places=2)
    monthly_min_payment = models.DecimalField(max_digits=10, decimal_places=2)
    interest_rate = models.DecimalField(max_digits=5, decimal_places=2)
    strategy = models.CharField(max_length=20, choices=STRATEGY_CHOICES, default='avalanche')
    extra_monthly_payment = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    extra_yearly_payment = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='active')

    def save(self, *args, **kwargs):
        if self.remaining_balance <= 0:
            self.status = 'paid'
        super().save(*args, **kwargs)

    def __str__(self):
        return self.name

class BalanceSheet(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)

    # Personal Use Assets
    own_house = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    household_contents = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    personal_cars = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    other_personal_assets = models.DecimalField(max_digits=15, decimal_places=2, default=0)

    # Cash/Liquid Assets
    current_account = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    savings_account = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    cash_at_hand = models.DecimalField(max_digits=15, decimal_places=2, default=0)

    # Financial Assets
    wealth_mgt_fund = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    stocks_shares = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    money_market_funds = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    unit_linked_investments = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    cash_value_policies = models.DecimalField(max_digits=15, decimal_places=2, default=0)

    # Invested Assets
    real_estate = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    business_value = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    sacco_shares = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    retirement_plans = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    other_investments = models.DecimalField(max_digits=15, decimal_places=2, default=0)

    # Liabilities
    personal_loans = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    overdraft_balances = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    sacco_loans = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    car_loans = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    mortgages = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    creditors = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    credit_cards = models.DecimalField(max_digits=15, decimal_places=2, default=0)
    other_liabilities = models.DecimalField(max_digits=15, decimal_places=2, default=0)

    created_at = models.DateTimeField(auto_now_add=True)

    @property
    def total_assets(self):
        return (
            self.own_house + self.household_contents + self.personal_cars + self.other_personal_assets +
            self.current_account + self.savings_account + self.cash_at_hand +
            self.wealth_mgt_fund + self.stocks_shares + self.money_market_funds +
            self.unit_linked_investments + self.cash_value_policies +
            self.real_estate + self.business_value + self.sacco_shares +
            self.retirement_plans + self.other_investments
        )

    @property
    def total_liabilities(self):
        return (
            self.personal_loans + self.overdraft_balances + self.sacco_loans + self.car_loans +
            self.mortgages + self.creditors + self.credit_cards + self.other_liabilities
        )

    @property
    def net_worth(self):
        return self.total_assets - self.total_liabilities


class InvestmentCalculation(models.Model):
    starting_amount = models.FloatField()
    return_rate = models.FloatField()
    additional_contribution = models.FloatField()
    years = models.IntegerField()
    compound = models.CharField(max_length=10, choices=[('annually', 'Annually'), ('monthly', 'Monthly')])
    contribute_at = models.CharField(max_length=10, choices=[('beginning', 'Beginning'), ('end', 'End')])
    created_at = models.DateTimeField(auto_now_add=True)


class FinancialProjection(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    initial_capital = models.FloatField()
    savings_range = models.JSONField()
    roi_range = models.JSONField()
    expense_range = models.JSONField()
    inflation_range = models.JSONField()
    created_at = models.DateTimeField(auto_now_add=True)

