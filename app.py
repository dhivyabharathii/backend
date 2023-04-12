from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import psycopg2
from flask_bcrypt import Bcrypt
import jwt
import datetime
from functools import wraps


app = Flask(__name__)
app.config['SECRET_KEY'] = '5791628bb0b13ce0c676dfde280ba245'

pg_user="postgres"
pg_pwd="password"
pg_port ="5432"
app.config['SQLALCHEMY_DATABASE_URI']='postgresql://{username}:{password}@localhost:{port}/flaskk'.format(username=pg_user,password=pg_pwd,port=pg_port)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=False
db=SQLAlchemy(app)
bcrypt = Bcrypt(app)


class RegisteredUsers(db.Model):
    id=db.Column(db.Integer,primary_key=True)
    username=db.Column(db.String(50),unique=True,nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password= db.Column(db.String(340),nullable=False)
    admin=db.Column(db.Boolean)
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = RegisteredUsers.query.filter_by(id=data['id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated
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
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        
        user_data = {}
        user_data['id'] = current_user.id
        user_data['username'] = current_user.username
        user_data['password'] = current_user.password
        user_data['admin'] = current_user.admin

        return jsonify({'user' : user_data})
    else:
        

        users = RegisteredUsers.query.all()

        output = []

        for user in users:
            user_data = {}
            user_data['id'] = user.id
            user_data['username'] = user.username
            user_data['password'] = user.password
            user_data['admin'] = user.admin
            output.append(user_data)

        return jsonify({'users' : output})


@app.route('/login',methods=['GET','POST'])
def login():
    # auth=request.authorization
    # if not auth or not auth.username or not auth.password:
    #     return jsonify({'message': 'Invalid'})
    email = request.json['email']
    password = request.json['password']
    user = RegisteredUsers.query.filter_by(email=email).first()
    
    if user and bcrypt.check_password_hash(user.password, password)  :
        token= jwt.encode({'id' : user.id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token':token.decode('UTF-8')})
    else:
        return jsonify({'message': 'Invalid credentials!'})

       
    
if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(host='0.0.0.0',port=5000,debug=True)