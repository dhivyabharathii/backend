from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import psycopg2
from flask_bcrypt import Bcrypt
import jwt
import datetime
from flask_jwt_extended import JWTManager, jwt_required, create_access_token,get_jwt_identity
from functools import wraps
from dotenv import load_dotenv
import os


load_dotenv()
Database_url=os.getenv('Database_url')
secret=os.getenv('secret')

app = Flask(__name__)
app.config['SECRET_KEY']=secret
app.config['SQLALCHEMY_DATABASE_URI']=Database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['JWT_SECRET_KEY'] = 'super-secret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600
db=SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt=JWTManager(app)

from pack.admin_rights.routes import bp
app.register_blueprint(bp,url_prefix ='/admin')
from pack.user_rights.routes import user
app.register_blueprint(user,url_prefix ='/users')