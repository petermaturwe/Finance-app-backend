from django.urls import path, include
from rest_framework.routers import DefaultRouter
from .views import *
from rest_framework_simplejwt.views import (TokenRefreshView,)



urlpatterns = [
    # Authentication Endpoints
   
    path('register/', RegisterView.as_view(), name='register'),
    path('verify-email/', VerifyUserEmail.as_view(), name='verify'),
    path('login/', LoginUserView.as_view(), name='login-user'),
    path('logout/', LogoutApiView.as_view(), name='logout'),
    path('resend-otp/', ResendOTPView.as_view(), name='resend-otp'),
        # Token Management
    path('token/refresh/', ExtendedTokenRefreshView.as_view(), name='token-refresh'),
    
    # Password Reset Flow
    path('check-email/', CheckEmailExistsView.as_view(), name='check-email'),
  path('password-reset/', PasswordResetRequestView.as_view(), name='password-reset-request'),
    path('password-reset/verify-otp/', VerifyOTPView.as_view(), name='password-reset-verify-otp'),
    path('password-reset/confirm-otp/', SetNewPasswordOTPView.as_view(), name='password-reset-confirm-otp'),
    
    path('api/user/profile/', UserProfileView.as_view(), name='user-profile'),
    path('api/auth/change-password/', ChangePasswordView.as_view(), name='change-password'),
    path('api/user/profile/photo/', ProfilePhotoUploadView.as_view(), name='profile-photo'),
    
    
  
    # Savings Goal Endpoints (explicitly defined)
    path('savings/categories/', GoalCategoryViewSet.as_view({'get': 'list', 'post': 'create'}), name='categories-list'),
    path('savings/categories/<int:pk>/', GoalCategoryViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='category-detail'),
    path('savings/goals/', SavingsGoalViewSet.as_view({'get': 'list', 'post': 'create'}), name='goals-list'),
    path('savings/goals/<int:pk>/', SavingsGoalViewSet.as_view({'get': 'retrieve', 'put': 'update', 'patch': 'partial_update', 'delete': 'destroy'}), name='goal-detail'),
    path('savings/goals/<int:pk>/mark-complete/', SavingsGoalViewSet.as_view({'post': 'mark_complete'}), name='goal-mark-complete'),
    path('savings/goals/<int:pk>/contributions/', SavingsGoalViewSet.as_view({'get': 'contributions','post': 'add_contribution'}), name='goal-contributions'),
    
    path('savings/summary/', GoalSummaryAPIView.as_view(), name='goal-summary'),
    path('savings/goals/<int:goal_id>/contributions/<int:pk>/', ContributionDetailAPIView.as_view(), name='goal-contribution-detail'),
    

    # Personal Budget endpoints
    path('budget/', PersonalBudgetListCreateView.as_view(), name='budget-list-create'),
    path('budget/<int:pk>/', PersonalBudgetDetailView.as_view(), name='budget-detail'),
    
    # Budget Expense Items endpoints
    path('budget/<int:budget_id>/expenses/', BudgetExpenseItemListCreateView.as_view(), name='budget-expense-list-create'),
    path('budget/expenses/<int:pk>/', BudgetExpenseItemDetailView.as_view(), name='budget-expense-detail'),
    
    # Custom Category endpoints
    path('budget/categories/', CustomCategoryListCreateView.as_view(), name='custom-category-list-create'),
    
    # Budget Rules endpoints
    path('budget/rules/', budget_rules_info, name='budget-rules-info'),
    path('budget/create-rule-based/', create_rule_based_budget, name='create-rule-based-budget'),
    
    # Utility endpoints
    path('budget/current-datetime/', current_datetime_eat, name='current-datetime-eat'),
    
    # Special action endpoints
    path('budget/expenses/<int:expense_id>/mark-paid/', mark_expense_as_paid, name='mark-expense-paid'),
    path('budget/<int:budget_id>/summary/', budget_summary, name='budget-summary'),
    path('budget/analytics/', user_budget_analytics, name='budget-analytics'),

    path('debts/', DebtListCreateView.as_view(), name='debt-list-create'),
    path('debts/<int:pk>/', DebtDetailView.as_view(), name='debt-detail'),
    path('debts/strategy/', DebtRepaymentStrategyView.as_view(), name='debt-repayment-strategy'),
    path('debts/delete-all/', DeleteDebtsView.as_view(), name='debt-delete-all'),

    path('balance-sheet/', BalanceSheetListCreateView.as_view(), name='balance-sheet-create'),
    path('balancesheet/<int:pk>/', BalanceSheetDetailView.as_view(), name='balancesheet-detail'),

    path('investment-calc/', InvestmentCalculationView.as_view(), name='investment-calc'),
    
    #financial projections
    path('projections/', FinancialProjectionListCreateView.as_view(), name='projection-list-create'),
    path('projections/<int:pk>/', FinancialProjectionDetailView.as_view(), name='projection-detail'),
    path('projections/<int:pk>/details/', FinancialProjectionCalculationView.as_view(), name='projection-details'),
    path('projections/<int:pk>/projection/', FinancialProjectionResultView.as_view(), name='projection-calculation'),

    
    

    
]