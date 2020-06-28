import requests
import json
import os
import shutil
import tarfile

import logging
logger = logging.getLogger(__name__)

import urllib3
from urllib3.exceptions import InsecureRequestWarning
urllib3.disable_warnings(InsecureRequestWarning)


class VRli():
    def __init__(self, ipaddress, username, password, provider):
        self.ipaddress = ipaddress
        self.username = username
        self.password = password
        self.provider = provider
        self.headers = {
            'Content-Type': 'application/json',
            'Accept': 'application/json',
        }
        self.rest_port = 9543
        self.baseuri = 'https://{0}:{1}'.format(self.ipaddress, self.rest_port)

        self.set_token()

    def set_token(self):
        body = {
            'username': self.username,
            'password': self.password,
            'provider': self.provider
        }
        # POST to fetch token
        token = self.post(
            urlsuffix='/api/v1/sessions',
            headers=self.headers,
            reqbody=json.dumps(body)
        )
        logger.debug(token)
        # Update headers
        self.headers['Authorization'] = 'Bearer {}'.format(
            token.get('sessionId')
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
