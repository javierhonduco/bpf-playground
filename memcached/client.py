import time
from pymemcache.client.base import Client


client = Client(('localhost', 11211))
print("[info] sending commands to memcached")
while True:
    client.stats()
    for i in range(5):
        client.get('a')
    time.sleep(1)
