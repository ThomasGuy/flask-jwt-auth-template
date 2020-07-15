# project/tests/test_user_model.py
import unittest
import datetime

from flask_jwt_extended import create_access_token, decode_token

from backendAPI.database import db_scoped_session as db
from backendAPI.database.models import User
from backendAPI.test.base import BaseTestCase
from backendAPI.server.util.blacklist_helpers import is_token_revoked, add_token_to_database

class TestUserModel(BaseTestCase):

    def test_decode_access_token(self):
        """ test decode access token """

        user = User(
            email='test@test.com',
            password='testpw',
            username='jonny'
        )
        db.add(user)
        db.commit()
        access_token = create_access_token(identity=user.public_id)
        add_token_to_database(access_token)
        self.assertTrue(User.authenticate( password='testpw', username='jonny'))
        self.assertTrue(User.authenticate( password='testpw', email='test@test.com'))
        self.assertTrue(User.authenticate( password='testpw', public_id=decode_token(access_token)['identity']))
        self.assertTrue(user.check_password(password='testpw'))
        self.assertTrue(decode_token(access_token)['identity'] == user.public_id)
        self.assertFalse(is_token_revoked(decode_token(access_token)))


if __name__ == '__main__':
    unittest.main()
