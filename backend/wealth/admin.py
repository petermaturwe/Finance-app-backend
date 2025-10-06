from django.contrib import admin
from .models import *
from django.utils.html import format_html

# Register your models here.

class UserAdmin(admin.ModelAdmin):
    list_display = ['id', 'email', 'first_name',
                    'last_name', 'is_staff', 'is_superuser', 'is_verified', 'is_active', 'date_joined', 'last_login', 'auth_provider']
    list_filter = ['is_staff', 'is_superuser', 'is_active', 'is_verified']


admin.site.register(User, UserAdmin)
admin.site.register(OneTimePassword)
admin.site.register(Debt)
admin.site.register(InvestmentCalculation)
admin.site.register(FinancialProjection)
@admin.register(PersonalBudget)
class PersonalBudgetAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'budget_period_start', 'budget_period_end', 'total_income', 'is_active')
    list_filter = ('is_active',)
    search_fields = ('name', 'user__username')

@admin.register(BudgetExpenseItem)
class BudgetExpenseItemAdmin(admin.ModelAdmin):
    list_display = ('item_name', 'budget', 'category', 'planned_expense', 'actual_expense', 'is_paid')
    list_filter = ('category', 'priority', 'is_paid')
    search_fields = ('item_name', 'notes')

@admin.register(CustomCategory)
class CustomCategoryAdmin(admin.ModelAdmin):
    list_display = ('name', 'user', 'description')
    search_fields = ('name', 'description')

#savings admin.py
@admin.register(GoalCategory)
class GoalCategoryAdmin(admin.ModelAdmin):
    """Admin for GoalCategory model"""
    list_display = ('name', 'created_by', 'is_default', 'created_at')
    list_filter = ('is_default',)
    search_fields = ('name', 'description')
    readonly_fields = ('created_at',)
    fieldsets = (
        ('Category Information', {
            'fields': ('name','is_default', 'created_by')
        }),
        ('Metadata', {
            'fields': ('created_at',),
            'classes': ('collapse',)
        }),
    )


class ContributionInline(admin.TabularInline):
    """Inline admin for contributions within a savings goal"""
    model = Contribution
    extra = 0
    fields = ('amount', 'notes', 'contribution_date')
    readonly_fields = ('created_at',)


@admin.register(SavingsGoal)
class SavingsGoalAdmin(admin.ModelAdmin):
    """Admin for SavingsGoal model with customizations"""
    list_display = ('name', 'user', 'target_amount', 'current_amount', 
                   'deadline', 'progress_bar', 'status', 'category', 'created_at')
    list_filter = ('is_completed', 'deadline', 'created_at', 'category')
    search_fields = ('name', 'description', 'user__email', 'user__first_name', 'user__last_name')
    readonly_fields = ('current_amount', 'created_at', 'updated_at', 'progress_percentage')
    inlines = [ContributionInline]
    date_hierarchy = 'created_at'
    
    fieldsets = (
        ('Goal Information', {
            'fields': ('user', 'name', 'description', 'category')
        }),
        ('Financial Details', {
            'fields': ('target_amount', 'current_amount', 'progress_percentage')
        }),
        ('Status', {
            'fields': ('deadline', 'is_completed')
        }),
        ('Metadata', {
            'fields': ('created_at', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def progress_bar(self, obj):
        """Display a visual progress bar in the admin"""
        percent = obj.progress_percentage or 0
        bar_color = 'green'
        if percent < 33:
            bar_color = 'red'
        elif percent < 66:
            bar_color = 'orange'
            
        return format_html(
            '<div style="width:100px; border:1px solid #ccc;">'
            '<div style="width:{}px; height:20px; background:{};">&nbsp;</div>'
            '</div> {}%',
            percent, bar_color, percent
        )
    progress_bar.short_description = 'Progress'


@admin.register(Contribution)
class ContributionAdmin(admin.ModelAdmin):
    """Admin for Contribution model"""
    list_display = ('id', 'amount', 'savings_goal', 'goal_owner', 'contribution_date', 'created_at')
    list_filter = ('contribution_date', 'created_at')
    search_fields = ('savings_goal__name', 'notes', 'savings_goal__user__email')
    readonly_fields = ('created_at',)
    date_hierarchy = 'contribution_date'
    
    def goal_owner(self, obj):
        """Display the user who owns the goal"""
        return obj.savings_goal.user
    goal_owner.short_description = 'User'
    goal_owner.admin_order_field = 'savings_goal__user'