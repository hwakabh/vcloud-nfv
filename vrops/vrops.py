import requests
import json

import logging
logger = logging.getLogger(__name__)

import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)


class VROps():
    def __init__(self, ipaddress, username, password):
        self.ipaddress = ipaddress
        self.username = username
        self.password = password
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        self.baseuri = 'https://{}'.format(self.ipaddress)

        self.set_suite_api_token()

    def set_suite_api_token(self):
        body = {
            'username': self.username,
            'password': self.password,
        }
        # POST to fetch token
        token = self.post(
            urlsuffix='/suite-api/api/auth/token/acquire',
            headers=self.headers,
            reqbody=json.dumps(body)
        )
        logger.debug(token)
        # Update headers
        self.headers['Authorization'] = 'vRealizeOpsToken {}'.format(token.get('token'))

    def casa_get(self, urisuffix):
        header = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        uri = '{0}{1}'.format(self.baseuri, urisuffix)
        res = requests.get(uri, headers=header, auth=(self.username, self.password), verify=False)
        logger.debug(json.loads(res.text))
        return json.loads(res.text)

    def get(self, urisuffix):
        uri = '{0}{1}'.format(self.baseuri, urisuffix)
        res = requests.get(uri, headers=self.headers, verify=False)
        logger.debug(json.loads(res.text))
        return json.loads(res.text)

    # POST for fetch suite-api token
    def post(self, urlsuffix, headers=None, reqbody=None):
        uri = '{0}{1}'.format(self.baseuri, urlsuffix)
        res = requests.post(uri, headers=self.headers, data=reqbody, verify=False)
        logger.debug(json.loads(res.text))
        return json.loads(res.text)
