from flask import Blueprint

from .registerAPI import RegisterAPI
from .loginAPI import LoginAPI
from .logoutAPI import LogoutAPI
from .refreshAPI import RefreshToken
from .protectedAPI import ProtectedAPI


auth_blueprint = Blueprint('auth', __name__)

registration_view = RegisterAPI.as_view('register_api')
login_view = LoginAPI.as_view('login_api')
logout_view = LogoutAPI.as_view('logout_api')
refresh_view = RefreshToken.as_view('refresh_api')
protected_view = ProtectedAPI.as_view('protected_api')


auth_blueprint.add_url_rule(
    '/auth/register',
    view_func=registration_view,
    methods=['POST']
)

auth_blueprint.add_url_rule(
    '/auth/login',
    view_func=login_view,
    methods=['POST']
)

auth_blueprint.add_url_rule(
    '/auth/logout',
    view_func=logout_view,
    methods=['GET']
)

auth_blueprint.add_url_rule(
    '/auth/refresh',
    view_func=refresh_view,
    methods=['GET']
)

auth_blueprint.add_url_rule(
    '/protected',
    view_func=protected_view,
    methods=['GET']
)
