from rest_framework import status, viewsets
from rest_framework.response import Response

from django.shortcuts import render

from .serializers import WalletAddressSerializer
from .models import WalletAddress

class WalletAddressViewset(viewsets.ModelViewSet):
    """
    CRUD viewset for wallets
    """
    queryset = WalletAddress.objects.all()
    serializer_class = WalletAddressSerializer
