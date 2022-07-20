from pymemcache.client import base
client = base.Client(('127.0.0.1', 11211))

def cachecheck(domain):
    if client.get(domain) == None:
        client.set(domain, 1, expire=60*60*48)
        return False #it's not cached
    else:
        return True #it's cached

import re
#https://stackoverflow.com/a/3271667
bad_words = ["\.gov", "-", "\*", "\.net", "\.org", "smtp", "mail\.", "cpanel\.", "api\.", "link\.", "www\.", "\.edu", "\.gob", "cdn", "static", "autodiscover", "\.com", "\.co\."]
bad_words_re = re.compile("|".join(bad_words))

def filter_domain(domain):
    if bad_words_re.search(domain) == None:
        return True

import requests
headers = {'Authorization': 'Basic NOPE',}
def screenshot(domain):
    data = {'url': "https://" + str(domain)}
    requests.post('http://NOPE:8888/scan', headers=headers, data=data, verify=False)

import certstream
#https://github.com/CaliDog/certstream-python#usage
def print_callback(message, context):
    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

        if len(all_domains) == 0:
            domain = "NULL"
        else:
            domain = all_domains[0]
            if filter_domain(domain):
                if cachecheck(domain) == False: #not cached
                    screenshot(domain)


certstream.listen_for_events(print_callback, url='wss://certstream.calidog.io/')
