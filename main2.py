import requests
from requests.adapters import HTTPAdapter
from urllib3.poolmanager import PoolManager
import ssl

class SslAdapter(HTTPAdapter):
    """Custom SSL Adapter to enforce TLS."""
    def init_poolmanager(self, *args, **kwargs):
        context = ssl.create_default_context()
        kwargs['ssl_context'] = context
        return super(SslAdapter, self).init_poolmanager(*args, **kwargs)


proxy = "http://127.0.0.1:8888"  # Fiddler or Burp proxy
proxies = {
    "http": proxy,
    "https": proxy
}

session = requests.Session()
session.mount("https://", SslAdapter())

# Inspect HTTPS Traffic
try:
    url = "https://example.com/feed"  # Test URL
    response = session.get(url, proxies=proxies, verify=False)  # Skip verification for the proxy
    if "feed" in response.text:
        print("Keyword 'feed' detected in response!")
    else:
        print("No keyword found.")
except requests.exceptions.RequestException as e:
    print(f"Error: {e}")
