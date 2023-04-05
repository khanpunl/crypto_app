from rest_framework import serializers

from .models import WalletAddress, WalletPrivateKey
from .utils import WalletInterface, ServiceApiError


class PrivateKeyField(serializers.ModelSerializer):
    """
    Creates an instance of WalletPrivateKey model
    """
    private_key = serializers.CharField()

    class Meta:
        model = WalletPrivateKey
        fields = '__all__'


class WalletAddressSerializer(serializers.ModelSerializer):
    """
    CRUD serializer to create wallets
    """
    address = serializers.CharField(required=False, allow_null=True)

    def create(self, validated_data, *args, **kwargs):
        wallet_type = validated_data.get('wallet')
        if wallet_type:
            wallet = WalletInterface(wallet_type)
            addr = wallet.address
            pk = wallet.private_key

            if addr:
                validated_data['address'] = addr
                serializer = PrivateKeyField(data={"private_key": pk})
                if serializer.is_valid():
                    obj = serializer.save()

                    validated_data['private_key'] = obj
                    wallet = super().create(validated_data, *args, **kwargs)
                    return wallet
        
        raise ServiceApiError("Bad request")

    class Meta:
        model = WalletAddress
        exclude = ('private_key',)
