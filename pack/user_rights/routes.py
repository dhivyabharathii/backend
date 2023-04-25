from flask import request, jsonify

from flask_jwt_extended import JWTManager, jwt_required, create_access_token,get_jwt_identity
from functools import wraps
from flask import Blueprint
from pack import db,app,bcrypt,jwt
from pack.models import RegisteredUsers
user= Blueprint('user',__name__)

@user.route('/user', methods=['GET'])
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
@user.route('/search_users',methods=['POST'])
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

@user.route('/details',methods=['POST'])
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
@user.route('/users/<id>', methods=['DELETE'])
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

@user.route('/login',methods=['GET','POST'])
def login():
    email = request.json['email']
    password = request.json['password']
    user = RegisteredUsers.query.filter_by(email=email).first()    
    if user and bcrypt.check_password_hash(user.password, password)  :
        access_token = create_access_token(identity=user.id)       
        return jsonify(access_token=access_token), 200
    else:
        return jsonify({'message': 'Invalid credentials!'})
