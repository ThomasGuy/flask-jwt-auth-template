import unittest
import json
import time
import uuid
import datetime

from flask_jwt_extended import decode_token, get_jwt_identity

from backendAPI.database import db_scoped_session as db
from backendAPI.database.models import User, Blacklist
from backendAPI.test.base import BaseTestCase
from backendAPI.server.util.blacklist_helpers import is_token_revoked


class TestAuthBlueprint(BaseTestCase):

    def test_refresh_expired_token(self):
        """ Test - refreah expired token and access protected endpoint """
        with self.client:
            # user registration
            resp_register = self.register_user()
            data_register = json.loads(resp_register.data.decode())
            self.assertTrue(data_register['auth_token'])
            self.assertEqual(resp_register.status_code, 201)
            # user login
            resp_login = self.login_user(username='joeseph', email='joe@gmail.com', password='123456')
            data_login = json.loads(resp_login.data.decode())
            self.assertTrue(data_login['auth_token'])
            self.assertTrue(data_login['refresh_token'])
            self.assertEqual(resp_login.status_code, 201)
            # invalid token
            time.sleep(6)
            response = self.client.get(
                '/protected',
                headers=dict(
                    Authorization='Bearer ' + data_login['auth_token']
                )
            )
            data = json.loads(response.data.decode())
            self.assertTrue(data['sub_status'] == 42)
            self.assertTrue(data['msg'] == 'The access token has expired')
            self.assertEqual(response.status_code, 401)
            # get refresh access token
            refresh_response = self.client.get(
                '/auth/refresh',
                headers=dict(
                    Authorization='Bearer ' + data_login['refresh_token']
                )
            )
            data_refresh = json.loads(refresh_response.data.decode())
            self.assertTrue(data_refresh['access_token'])
            print('Access token', decode_token(data_refresh['access_token']))
            print('id ', get_jwt_identity())
            self.assertFalse(is_token_revoked(decode_token(data_refresh['access_token'])))
            response = self.client.get(
                '/protected',
                headers=dict(
                    Authorization='Bearer ' + data_refresh['access_token']
                )
            )
            data_final = json.loads(response.data.decode())
            # print('\nfinal response ', data_final)
