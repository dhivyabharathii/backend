from flask import request, jsonify

from flask_jwt_extended import JWTManager, jwt_required, create_access_token,get_jwt_identity
from functools import wraps
from flask import Blueprint
from pack import db,app,bcrypt,jwt
from pack.models import RegisteredUsers
bp= Blueprint('bp',__name__)

@bp.route('/register', methods=['POST'])
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



@bp.route('/user/<id>', methods=['PUT','POST'])
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

