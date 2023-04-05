import uuid

from django.db import models

from .utils import generate_uuid


class WalletPrivateKey(models.Model):
    uuid = models.UUIDField(default=generate_uuid)
    private_key = models.CharField(max_length=128)


class WalletAddress(models.Model):
    WALLET_TYPES = (
        ('ETH', 'Ethereum'),
        ('BTC', 'Bitcoin'),
    )
    uuid = models.UUIDField(default=generate_uuid)
    address = models.CharField(max_length=64)
    wallet = models.CharField(max_length=25, choices=WALLET_TYPES)
    private_key = models.ForeignKey(
        WalletPrivateKey, related_name='wallets', on_delete=models.CASCADE
    )
