# Copyright 2015 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import unittest

import flask
from six import iteritems
from talisman import ALLOW_FROM, DENY, Talisman


HTTPS_ENVIRON = {'wsgi.url_scheme': 'https'}


class TestTalismanExtension(unittest.TestCase):

    def setUp(self):
        self.app = flask.Flask(__name__)
        self.talisman = Talisman(self.app)
        self.client = self.app.test_client()

        self.app.route('/')(lambda: 'Hello, world')

    def testDefaults(self):
        # HTTPS request.
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)

        headers = {
            'X-Frame-Options': 'SAMEORIGIN',
            'Strict-Transport-Security':
            'max-age=31556926; includeSubDomains; preload',
            'X-XSS-Protection': '1; mode=block',
            'X-Content-Type-Options': 'nosniff',
            'Content-Security-Policy': 'default-src \'self\'',
            'X-Content-Security-Policy': 'default-src \'self\''
        }

        for key, value in iteritems(headers):
            self.assertEqual(response.headers.get(key), value)

    def testForceSslOptionOptions(self):
        # HTTP request from Proxy
        response = self.client.get('/', headers={
            'X-Forwarded-Proto': 'https'
        })
        self.assertEqual(response.status_code, 200)

        # HTTP Request, should be upgraded to https
        response = self.client.get('/')
        self.assertEqual(response.status_code, 302)
        self.assertTrue(response.headers['Location'].startswith('https://'))

        # Permanent redirects
        self.talisman.config['TALISMAN_FORCE_HTTPS_PERMANENT'] = True
        response = self.client.get('/')
        self.assertEqual(response.status_code, 301)

        # Disable forced ssl, should allow the request.
        self.talisman.config['TALISMAN_FORCE_HTTPS'] = False
        response = self.client.get('/')
        self.assertEqual(response.status_code, 200)

    def testHstsOptions(self):
        self.talisman.config['TALISMAN_FORCE_HTTPS'] = False

        # No HSTS headers for non-ssl requests
        response = self.client.get('/')
        self.assertTrue('Strict-Transport-Security' not in response.headers)

        # Secure request with HSTS off
        self.talisman.config['TALISMAN_STRICT_TRANSPORT_SECURITY'] = False
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertTrue('Strict-Transport-Security' not in response.headers)

        # No subdomains
        self.talisman.config['TALISMAN_STRICT_TRANSPORT_SECURITY'] = True
        self.talisman.config['TALISMAN_STRICT_TRANSPORT_SECURITY_INCLUDE_SUBDOMAINS'] = False
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertTrue(
            'includeSubDomains' not in
            response.headers['Strict-Transport-Security'])

    def testFrameOptions(self):
        self.talisman.config['TALISMAN_FRAME_OPTIONS'] = DENY
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(response.headers['X-Frame-Options'], 'DENY')

        self.talisman.config['TALISMAN_FRAME_OPTIONS'] = ALLOW_FROM
        self.talisman.config['TALISMAN_FRAME_OPTIONS_ALLOW_FROM'] = 'example.com'
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(
            response.headers['X-Frame-Options'], 'ALLOW-FROM example.com')

    def testContentSecurityPolicyOptions(self):
        self.talisman.config['TALISMAN_CONTENT_SECURITY_POLICY']['image-src'] = '*'
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        csp = response.headers['Content-Security-Policy']
        self.assertTrue('default-src \'self\'' in csp)
        self.assertTrue('image-src *' in csp)

        self.talisman.config['TALISMAN_CONTENT_SECURITY_POLICY']['image-src'] = [
            "'self'",
            'example.com'
        ]
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        csp = response.headers['Content-Security-Policy']
        self.assertTrue('default-src \'self\'' in csp)
        self.assertTrue('image-src \'self\' example.com' in csp)

        # string policy
        self.talisman.config['TALISMAN_CONTENT_SECURITY_POLICY'] = 'default-src example.com'
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertEqual(response.headers['Content-Security-Policy'],
                         'default-src example.com')

        # no policy
        self.talisman.config['TALISMAN_CONTENT_SECURITY_POLICY'] = False
        response = self.client.get('/', environ_overrides=HTTPS_ENVIRON)
        self.assertTrue('Content-Security-Policy' not in response.headers)

    def testDecorator(self):

        @self.app.route('/nocsp')
        @self.talisman(content_security_policy=None)
        def nocsp():
            return 'Hello, world'

        response = self.client.get('/nocsp', environ_overrides=HTTPS_ENVIRON)
        self.assertTrue('Content-Security-Policy' not in response.headers)
        self.assertEqual(response.headers['X-Frame-Options'], 'SAMEORIGIN')
