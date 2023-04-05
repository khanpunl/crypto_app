from rest_framework import routers

from django.conf.urls import include, url
from django.urls import path

from .views import WalletAddressViewset


app_name = 'crypto_address'

router  = routers.DefaultRouter()
router.register(r'address', WalletAddressViewset, basename='address')

urlpatterns = [
    path('', include(router.urls)),
]
