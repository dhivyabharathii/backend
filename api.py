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

class RegisteredUsers(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(50),nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password= db.Column(db.String(340),nullable=False)
    admin=db.Column(db.Boolean)
    role = db.Column(db.String(50))
    manager_id=db.Column(db.Integer,db.ForeignKey('registered_users.id'))
    
@app.route('/register', methods=['POST'])
@jwt_required()
def register(): #to add users in db only by admin
    current_user_id = get_jwt_identity()
    current_user = RegisteredUsers.query.filter_by(id=current_user_id).first()
    if current_user.admin:  
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
    return jsonify({'message':'Not authorized'})

@app.route('/user', methods=['GET'])
@jwt_required()
def get_all_users():#to view all users in table
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
    return jsonify({'users':output_users})
@app.route('/search_users',methods=['POST'])
def search_users():#to search all users under particular role
    role= request.json['role']
    users=RegisteredUsers.query.filter_by(role=role).all()
    output_users=[]
    for user in users:
        user_name={}
        user_name['username'] = user.username
        user_name['id']=user.id        
        output_users.append(user_name)
    return jsonify({'users' : output_users})

@app.route('/details',methods=['POST'])
def display_details():#to display details of a particular person
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
            for reportee in reportees:#to show employees reporting to this manager
                user_name={}
                user_name['reportees'] = reportee.username        
                output_users.append(user_name)
        elif user.role=='employee':#shows the manager name (the employee reportimg to) 
            reportees=RegisteredUsers.query.filter_by(id=user.manager_id).first()
            output_users.append({'reports_t0':reportees.username})
        
        output_users.append(user_data)
    return jsonify(users=output_users)


@app.route('/user/<id>', methods=['PUT','POST'])
@jwt_required()
def update_userrole(id):#to update user role (promote,demote,assign role)
    current_user_id = get_jwt_identity()
    current_user = RegisteredUsers.query.filter_by(id=current_user_id).first()
    if current_user.admin:
        user = RegisteredUsers.query.filter_by(id=id).first()
        prev_role=user.role
        if not user:
            return jsonify({'message' : 'No user found!'})
        user.role=request.json['role']
        db.session.commit()
        if user.role=='manager' and prev_role=='employee':#promote
            user.manager_id=0
            db.session.commit()
            return jsonify({'message':' table updated'})
        elif user.role=='employee' and prev_role=='manager':#demote
            user = RegisteredUsers.query.filter_by(id=id).all() 
            #to assign manager id we have find the list of managers.In search_users route we can find list of managers          
            user.manager_id=request.json['manager_employee_id']
            db.session.commit()
            employees=RegisteredUsers.query.filter_by(manager_id=user.id).all()
            for employee in employees:
                employee.manager_id=None
                db.session.commit()
            return jsonify({'message':'manager to employee'})
        return jsonify({'message' : 'The user has been assigned with a Manager !'})
    return jsonify({'message':'You are not authorized!'})

@app.route('/users/<id>', methods=['DELETE'])
@jwt_required()
def delete_user():#to delete particular user
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