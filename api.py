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

class RegisteredUsers(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(50),unique=True,nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password= db.Column(db.String(340),nullable=False)
    admin=db.Column(db.Boolean)
    role = db.Column(db.String(50))
    manager_id=db.Column(db.Integer)
    
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
@app.route('/search_users',methods=['POST'])
def search_users():
    role= request.json['role']
    users=RegisteredUsers.query.filter_by(role=role).all()
    output_users=[]
    for user in users:
        user_name={}
        user_name['username'] = user.username        
        output_users.append(user_name)
    return jsonify({'users' : output_users})

@app.route('/details',methods=['POST'])
def display_details():
    username = request.json['username']
    users=RegisteredUsers.query.filter_by(username=username).all()
    output_users=[]
    for user in users:    
        user_data = {}
        user_data['id'] = user.id
        user_data['username'] = user.username
        user_data['admin'] = user.admin
        user_data['manager_id'] = user.manager_id
        user_data['role'] = user.role
        if user.role=='manager':
            reportees=RegisteredUsers.query.filter_by(manager_id=user.id).all()
            for reportee in reportees:
                user_name={}
                user_name['reportees'] = reportee.username        
                output_users.append(user_name)
        output_users.append(user_data)
    return jsonify({'users' : output_users})


@app.route('/user/<id>', methods=['PUT','POST'])
@jwt_required()
def update_userrole(id):
    current_user_id = get_jwt_identity()
    current_user = RegisteredUsers.query.filter_by(id=current_user_id).first()
    if current_user.admin:
        user = RegisteredUsers.query.filter_by(id=id).first()
        prev_role=user.role
        if not user:
            return jsonify({'message' : 'No user found!'})
        #user.manager_id = request.json['manager_id',None]
        user.role=request.json['role']
        db.session.commit()
        if user.role=='manager' and prev_role=='employee':
            user.manager_id=0
            db.session.commit()
            return jsonify({'message':'manager table updated'})
        elif user.role=='employee' and prev_role=='manager':
            user.manager_id=request.json['manager_employee_id']
            db.session.commit()
            return jsonify({'message':'manager to employee'})
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
