from flask import Flask, jsonify
from flask_jwt_extended import JWTManager

from backendAPI.database import init_db, db_scoped_session, flask_bcrypt
from backendAPI.server.util.blacklist_helpers import is_token_revoked


jwt = JWTManager()

def create_app(Config):
    app = Flask(__name__)
    app.config.from_object(Config)
    jwt.init_app(app)
    flask_bcrypt.init_app(app)
    engine = init_db(app.config.get('SQLALCHEMY_DATABASE_URI'))


    with app.app_context():
        from backendAPI.server.controllers import auth_blueprint
        app.register_blueprint(auth_blueprint)

        @jwt.expired_token_loader
        def my_expired_token_callback(expired_token):
            token_type = expired_token['type']
            return jsonify({
                'status': 401,
                'sub_status': 42,
                'token_type': token_type,
                'message': 'The {} token has expired'.format(token_type)
            }), 401

        @app.teardown_appcontext
        def shutdown_session(exception=None):
            db_scoped_session.remove()

    return app, engine
