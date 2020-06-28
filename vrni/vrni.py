import requests
import json

import logging
logger = logging.getLogger(__name__)

import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)


class VRni():
    def __init__(self, ipaddress, username, password, domain):
        self.ipaddress = ipaddress
        self.username = username
        self.password = password
        self.domain = domain
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        self.baseuri = 'https://{0}'.format(self.ipaddress)

        self.set_token()

    def set_token(self):
        body = {
            'username': self.username,
            'password': self.password,
            'domain': {
                'domain_type': self.domain
            }
        }
        # POST to fetch token
        token = self.post(
            urlsuffix='/api/ni/auth/token',
            headers=self.headers,
            reqbody=json.dumps(body)
        )
        logger.debug(token)
        # Update headers
        self.headers['Authorization'] = 'NetworkInsight {}'.format(
            token.get('token')
        )

    def get(self, urisuffix):
        uri = '{0}{1}'.format(self.baseuri, urisuffix)
        res = requests.get(
            uri,
            headers=self.headers,
            verify=False
        )
        logger.debug(json.loads(res.text))
        return json.loads(res.text)

    def post(self, urlsuffix, headers=None, reqbody=None):
        uri = '{0}{1}'.format(self.baseuri, urlsuffix)
        res = requests.post(
            uri,
            auth=(self.username, self.password),
            headers=self.headers,
            data=reqbody,
            verify=False
        )
        logger.debug(json.loads(res.text))
        return json.loads(res.text)
