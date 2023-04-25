
from flask_sqlalchemy import SQLAlchemy
import psycopg2
from pack import db,app
class RegisteredUsers(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(50),nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password= db.Column(db.String(340),nullable=False)
    admin=db.Column(db.Boolean)
    role = db.Column(db.String(50))
    manager_id=db.Column(db.Integer,db.ForeignKey('registered_users.id'))
with app.app_context():
        db.create_all()
    