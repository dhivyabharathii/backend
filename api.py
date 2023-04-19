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
app.config['SECRET_KEY'] ='5791628bb0b13ce0c676dfde280ba245'
app.config['SQLALCHEMY_DATABASE_URI']= 'postgresql://postgres:password@localhost:5432/flaskk'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
app.config['JWT_SECRET_KEY'] = 'super-secret'
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = 3600
db=SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt=JWTManager(app)


class Managers(db.Model):
    manager_name = db.Column(db.String(50),nullable=False)
    manager_id=db.Column(db.String(50),primary_key=True)
    relate= db.relationship('RegisteredUsers', backref='managers', lazy=True)

class RegisteredUsers(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(50),unique=True,nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password= db.Column(db.String(340),nullable=False)
    admin=db.Column(db.Boolean)
    role = db.Column(db.String(50))
    manager_id=db.Column(db.String(50),db.ForeignKey('managers.manager_id'))
@app.route('/join', methods=['GET'])
def join():
    posts = db.session.query(RegisteredUsers).join(Managers, RegisteredUsers.manager_id == Managers.manager_id).all()
    post_list = []
    for post in posts:
        post_dict = {
            'id': post.id,
            'username': post.username,
            'reports to': post.managers.manager_name
        }
        post_list.append(post_dict)
    return jsonify(post_list)

@app.route('/manager', methods=['POST'])
@jwt_required()
def manager():
    manager_name=request.json['manager_name']
    manager_id=request.json['manager_id']
    manager = Manangers.query.filter_by(manager_id=manager_id).first()
    if current_user.admin:

        if manager:
            return jsonify({'message':'Manager ID exists'})
        else:
            manager = Managers(manager_name=manager_name,manager_id=manager_id)
            db.session.add(manager)
            db.session.commit()
            return jsonify({'message':'manager_id Added'})
    else:
        return jsonify({'message':'Not authorized'})

@app.route('/register', methods=['POST'])
def register():
    
    username = request.json['username']
    email=request.json['email']
    password = request.json['password']
    admin=request.json['admin']
    user = RegisteredUsers.query.filter_by(email=email).first()
    if user:
        return jsonify({'message': 'User already exists!'})

    else:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        user = RegisteredUsers(username=username, email=email, password=hashed_password,admin=admin)
        db.session.add(user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully!'})

@app.route('/user', methods=['GET'])
@jwt_required()
def get_all_users():
    current_user_id = get_jwt_identity()
    current_user = RegisteredUsers.query.filter_by(id=current_user_id).first()


    # if not current_user.admin:        
    #     user_data = {}
    #     user_data['id'] = current_user.id
    #     user_data['username'] = current_user.username
    #     user_data['password'] = current_user.password
    #     user_data['admin'] = current_user.admin
    #     return jsonify({'user' : user_data})
    # else:
    users = RegisteredUsers.query.all()
    output_users = []
    for user in users:
        user_data = {}
        user_data['id'] = user.id
        user_data['username'] = user.username
        user_data['admin'] = user.admin
        user_data['manager_id'] = user.manager_id
        user_data['role'] = user.role

        output_users.append(user_data)
    managers = Managers.query.all()
    output_managers=[]
    for manager in managers:
        manager_data = {}
        manager_data['manager_name'] =manager.manager_name
        manager_data['manager_id'] =manager.manager_id
        output_managers.append(manager_data)

    return jsonify({'users' : output_users,'managers':output_managers})
@app.route('/user/<id>', methods=['PUT','POST'])
@jwt_required()
def update_user(id):
    current_user_id = get_jwt_identity()
    current_user = RegisteredUsers.query.filter_by(id=current_user_id).first()
    if current_user.admin:
        user = RegisteredUsers.query.filter_by(id=id).first()
        prev_role=user.role

        if not user:
            return jsonify({'message' : 'No user found!'})
        # if user.role:
        #     current_role=user.role
        #     user.manager_id = request.json['manager_id']
        #     user.role=request.json['role']
        # db.session.commit()

        user.manager_id = request.json['manager_id']
        user.role=request.json['role']
        db.session.commit()
        if user.role=='manager':
            manager_table_id=request.json['manager_id']
            manager=Managers(manager_name=user.username,manager_id=manager_table_id)
            db.session.add(manager)
            db.session.commit()
            return jsonify({'message':'manager table updated'})
        if prev_role=='manager':
            manager_table_id=request.json['manager_id']
            manager=Managers.query.filter_by(manager_id=manager_table_id)

            db.session.delete(manager)
            db.session.commit()
            return jsonify({'message':'manager table updated-delete'})
        return jsonify({'message' : 'The user has been assigned with a Manager !'})
    return jsonify({'message':'You are not authorized!'})

@app.route('/users/<id>', methods=['DELETE'])
@jwt_required()
def delete_user():
    current_user_id = get_jwt_identity()
    current_user = RegisteredUsers.query.filter_by(id=current_user_id).first()

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = RegisteredUsers.query.filter_by(id=id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})


@app.route('/login',methods=['GET','POST'])
def login():
    email = request.json['email']
    password = request.json['password']
    user = RegisteredUsers.query.filter_by(email=email).first()
    
    if user and bcrypt.check_password_hash(user.password, password)  :
        access_token = create_access_token(identity=user.id)       
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({'message': 'Invalid credentials!'})
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(host='0.0.0.0',port=5000,debug=True)