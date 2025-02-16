from django.urls import path
from .views import (
    RegisterView, LoginView, SubscriptionView, ProfileView,
    SendOTPView, VerifyOTPRegisterView, CreateOrderView, VerifyPaymentView,ResetPasswordView,generate_questions)
import api.views as views

urlpatterns = [
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('subscription/', SubscriptionView.as_view(), name='subscription'),
    path('profile/', ProfileView.as_view(), name='profile'),
    path('send-otp/', SendOTPView.as_view(), name='send-otp'),
    path('verify-otp-register/', VerifyOTPRegisterView.as_view(), name='verify-otp-register'),
    path('create-order/', CreateOrderView.as_view(), name='create-order'),
    path('verify-payment/', VerifyPaymentView.as_view(), name='verify-payment'),
    path('reset-password/', ResetPasswordView.as_view(), name='reset-password'),
    path('generate-questions/', views.generate_questions, name='generate-questions'),
]
