import enum
import jwt

from datetime import datetime, timedelta
from flask import Flask, request, jsonify
from flask_restful import Api, Resource, abort
from flask_sqlalchemy import SQLAlchemy
from decouple import config
from werkzeug.security import generate_password_hash, check_password_hash
from sqlalchemy.exc import IntegrityError

app = Flask(__name__)

db_user = config("DB_USER")
db_password = config("DB_PASSWORD")
db_port = config("DB_PORT")
db_name = config("DB_NAME")

app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{db_user}:{db_password}@localhost:{db_port}/{db_name}'

db = SQLAlchemy(app)
api = Api(app)


class UserRoleEnum(enum.Enum):
    admin = "admin"
    user = "user"


class UserModel(db.Model):
    __tablename__ = "users"
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, unique=True)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum(UserRoleEnum), default=UserRoleEnum.user, nullable=False)
    portfolio_id = (db.Integer, db.ForeignKey("portfolio.id"))
    
    def encode_token(self):
        try:
            payload = {
                'exp': datetime.utcnow() + timedelta(days=2),
                'sub': self.id
            }
            return jwt.encode(
                payload,
                key=config("SECRET_KEY"),
                algorithm="HS256")
        except Exception as e:
            raise e

    @staticmethod
    def decode_token(auth_token):
        try:
            key = config("SECRET_KEY")
            payload = jwt.decode(jwt=auth_token, key=key, algorithms=["HS256"])
            return payload["sub"]
        except jwt.ExpiredSignatureError as ex:
            raise ex
        except jwt.InvalidTokenError as ex:
            raise ex
        except Exception as ex:
            raise ex


class CryptoPriceModel(db.Model):
    __tablename__ = "price"
    id = db.Column(db.Integer, primary_key=True)
    bitcoin = db.Column(db.Float, default=0)
    ethereum = db.Column(db.Float, default=0)
    polkadot = db.Column(db.Float, default=0)


class UserPortfolioModel(db.Model):
    __tablename__ = "portfolio"
    id = db.Column(db.Integer, primary_key=True)
    bitcoin = db.Column(db.Float, default=0)
    ethereum = db.Column(db.Float, default=0)
    polkadot = db.Column(db.Float, default=0)


class SingUp(Resource):
    def post(self):
        data = request.get_json()
        data["password"] = generate_password_hash(data["password"], method="sha256")
        try:
            user = UserModel(**data)
            db.session.add(user)
            db.session.commit()
            token = user.encode_token()
            return {"token": token}, 201
        except IntegrityError:
            return "This email is already used by another user"




db.create_all()
api.add_resource(SingUp, "/")


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True)
