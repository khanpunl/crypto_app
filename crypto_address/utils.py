import base58
import codecs
import ecdsa
import hashlib
import re
import secrets
import uuid
from abc import ABCMeta, abstractmethod

from web3 import Web3
import bcrypt
from ecpy.curves import Curve
from ecpy.keys import ECPublicKey, ECPrivateKey
from Crypto.Hash import keccak

from rest_framework import status
from rest_framework.exceptions import APIException


def generate_uuid():
    """
    returns a uuid object
    """
    return uuid.uuid4()


class AppBaseException(APIException):
    def __init__(self, detail=None, code=None, *args, **kwargs):
        super().__init__(detail=detail, code=code)


class ServiceApiError(AppBaseException):
    """
    raise an instance of this class in case of an API error
    """
    status_code = status.HTTP_400_BAD_REQUEST
    default_detail = ('Requested data defect')
    default_code = 'data_defect'


class Currency(metaclass=ABCMeta):
    """
    Abstract base class for different types of crypto currencies
    """
    @abstractmethod
    def get_private_key(self):
        """
        Method to create a private key
        """
        pass

    @abstractmethod
    def get_address(self):
        """
        Method to verify the validity of an ethereum address
        """
        pass

    @abstractmethod
    def verify_address(self):
        """
        Method to create an ethereum address
        """
        pass


class Ethereum(Currency):
    def __init__(self):
        self.private_key = self.get_private_key()
        self.address = self.get_address()

    def get_private_key(self):
        priv = secrets.token_hex(32)
        private_key_str = "0x" + priv

        return private_key_str

    def get_address(self):
        private_key = int(self.private_key, 16)
        cv = Curve.get_curve('secp256k1')
        pv_key = ECPrivateKey(private_key, cv)
        pu_key = pv_key.get_public_key()
        keccak_256 = keccak.new(digest_bits=256)
        concat_x_y = pu_key.W.x.to_bytes(32, byteorder='big') \
            + pu_key.W.y.to_bytes(32, byteorder='big')

        eth_addr = '0x' + keccak_256.update(concat_x_y).digest()[-20:].hex()

        # if self.verify_address(eth_addr):
        #     return eth_addr
        # return

        return eth_addr

    @staticmethod
    def verify_address(address):
        #Connect to INFURA HTTP End Point
        infura_url='https://mainnet.infura.io/v3/29547...' #your uri
        infura_url='https://mainnet.infura.io/v3/30faac9a813f41a69baab829ffe50371'
        w3 = Web3(Web3.HTTPProvider(infura_url))

        if w3.is_connected():
            return w3.is_address(address)


class BitCoin(Currency):
    def __init__(self):
        self.private_key = self.get_private_key()
        self.address = self.get_address()

    def get_private_key(self):
        priv = secrets.token_hex(32)
        private_key_str = priv

        return private_key_str

    def get_address(self):
        private_key = self.private_key
        # Hex decoding the private key to bytes using codecs library
        private_key_bytes = codecs.decode(private_key, 'hex')

        # Generating a public key in bytes using SECP256k1 & ecdsa library
        public_key_raw = ecdsa.SigningKey.from_string(
            private_key_bytes, curve=ecdsa.SECP256k1
        ).verifying_key
        public_key_bytes = public_key_raw.to_string()

        # Hex encoding the public key from bytes
        public_key_hex = codecs.encode(public_key_bytes, 'hex')

        # Bitcoin public key begins with bytes 0x04
        # so we have to add the bytes at the start
        public_key = (b'04' + public_key_hex).decode("utf-8")

        # Checking if the last byte is odd or even
        if (ord(bytearray.fromhex(public_key[-2:])) % 2 == 0):
            public_key_compressed = '02'
        else:
            public_key_compressed = '03'

        # Add bytes 0x02 to the X of the key if even or 0x03 if odd
        public_key_compressed += public_key[2:66]

        # Converting to bytearray for SHA-256 hashing
        hex_str = bytearray.fromhex(public_key_compressed)
        sha = hashlib.sha256()
        sha.update(hex_str)

        # Perform RIPMED-160 hashing on the result of SHA-256
        rip = hashlib.new('ripemd160')
        rip.update(sha.digest())
        key_hash = rip.hexdigest()

        # Add version byte in front of RIPEMD-160 hash (0x00 for Main Network)
        modified_key_hash = "00" + key_hash

        # Perform SHA-256 hash on the extended RIPEMD-160 result
        sha = hashlib.sha256()
        hex_str = bytearray.fromhex(modified_key_hash)
        sha.update(hex_str)

        # Perform SHA-256 hash on the result of the previous SHA-256 hash
        sha_2 = hashlib.sha256()
        sha_2.update(sha.digest())

        # Take the first 4 bytes of the second SHA-256 hash
        # this is the address checksum
        checksum = sha_2.hexdigest()[:8]

        # Add the 4 checksum bytes from stage 8 at the end of
        # extended RIPEMD-160 hash from stage 5
        # this is the 25-byte binary Bitcoin Address
        byte_25_address = modified_key_hash + checksum

        # Convert the result from a byte string into a
        # base58 string using Base58Check encoding
        btc_addr = base58.b58encode(
            bytes(bytearray.fromhex(byte_25_address))
        ).decode('utf-8')

        if self.verify_address(btc_addr):
            return btc_addr
        return

    @staticmethod
    def verify_address(address):
        # Regex to check valid BITCOIN Address
        regex = "^(bc1|[13])[a-km-zA-HJ-NP-Z1-9]{25,34}$"
    
        # Compile the ReGex
        pttrn = re.compile(regex)

        # If the string is empty
        # return false
        if (address == None):
            return False
    
        return re.search(pttrn, address)


class WalletInterface:
    WALLETS = {
        'ETH': Ethereum(),
        'BTC': BitCoin()
    }

    def __init__(self, wallet):
        self.wallet = wallet
        self.address = self.get_wallet_address()
        self.private_key = self.get_private_key()

    def get_wallet_address(self):
        obj = self.WALLETS.get(self.wallet)
        return obj.address

    def get_private_key(self):
        obj = self.WALLETS.get(self.wallet)
        return obj.private_key
