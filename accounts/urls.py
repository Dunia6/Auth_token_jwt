from django.urls import path, include
from rest_framework import routers
from . import views

router = routers.DefaultRouter()
router.register(r'register', views.RegisterViewSet, basename='Register')
router.register(r'profile', views.UserProfileViewSet, basename='UserProfile')


urlpatterns = [
    path('', include(router.urls)),
    path('login/', views.LoginView.as_view(), name='login'),
    path('logout/', views.LogoutView.as_view(), name='logout'),
    path('update/profile/', views.UserProfileUpdateViewSet.as_view({'put': 'update'}), name='update_profile'),
    path('change_password/', views.ChangePasswordViewSet.as_view({'post':'change_password'}), name='change_password'),
    path('refreshAccessToken/', views.RefreshAccessTokenView.as_view(), name='refresh_access_token'),
]