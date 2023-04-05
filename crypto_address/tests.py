from django.test import TestCase

from .utils import BitCoin, Ethereum

# Create your tests here.
class ViewsTestCase(TestCase):
    def test_get_api(self):
        """The index page loads properly"""
        response = self.client.get('http://127.0.0.1/:8000')
        self.assertEqual(response.status_code, 404)

    def test_bitcoin_address(self):
        btc = BitCoin()
        btc.private_key = "18e14a7b6a307f426a94f8114701e7c8e774e7f9a47e2c2035db29a206321725"
        address = btc.get_address()

        self.assertEqual(address, "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs")

    def test_ethereum_address(self):
        eth = Ethereum()
        eth.private_key = "0xb0ac4403b6b0c61d4cf260195035b1944140f28b71b0da06cb06c9601a9d2856"
        address = eth.get_address()

        self.assertEqual(address, "0x4f76155123f5566b7a5dfaaf36c129d49c676ad8")
