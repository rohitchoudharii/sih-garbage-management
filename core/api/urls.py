from django.urls import path, include
from .views import (
    CurrentUserAPIView,
    UserView,
    GoogleLogin,
    DeleteAllUnexpiredSessionsForUser

)
from rest_framework import routers
router = routers.DefaultRouter()
router.register('', UserView)

app_name = 'core-api'

urlpatterns = [
    path('current/details/', CurrentUserAPIView.as_view(),name='current-user-api'),
    path('', include(router.urls)),
    path('sessions/all/delete/', DeleteAllUnexpiredSessionsForUser.as_view(),name='del'),
    path('google/', GoogleLogin.as_view(), name='google_login'),

]
