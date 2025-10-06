from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse
from datetime import datetime

def health_check(request):
    """Health check for AWS App Runner"""
    return JsonResponse({
        "status": "healthy",
        "user": "petermaturwe",
        "timestamp": datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
        "deployment_time": "2025-08-10 21:09:50 UTC"
    })

def api_info(request):
    """API information"""
    return JsonResponse({
        "api": "WealthPro REST API",
        "user": "petermaturwe",
        "version": "1.0.0",
        "deployment_time": "2025-08-10 21:09:50 UTC",
        "endpoints": {
            "health": "/health/",
            "admin": "/admin/",
            "api": "/api/",
        }
    })

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', include('wealth.urls')),
    path('health/', health_check, name='health_check'),
    path('', api_info, name='api_info'),
]