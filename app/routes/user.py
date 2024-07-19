from flask import Blueprint, jsonify, request, json, make_response
from flask_restful import Resource, Api
from app import app
from flask_bcrypt import Bcrypt 
from app.models import User
from app import db
from app.schemas import UserSchema
from pydantic import ValidationError
import re
from app import mail 
from flask_mail import Message
import threading
from flask import current_app
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity, get_jwt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required

user_bp = Blueprint('users',__name__)

api = Api(user_bp)
bcrypt = Bcrypt(app)
# @user_bp.route("/",methods=['GET','POST'])
# def index():
#     return "Hello"

jwt = JWTManager(app)

def validate_user_data(data):
    email = data.get("email")
    username = data.get("username", None)
    name = data.get("name", None)
    password = data.get("password_hash", None)
    
    if name is None or str(name).strip() == "" or name != str(name):
        return {'Error': 'Please enter a valid name'}
    
    if User.query.filter_by(username=username).first() or len(str(username)) <= 4 or str(username).strip() == "" or username is None or username != str(username):
        return {'Error': 'Username is already present or username must contain at least 5 characters'}
    
    if User.query.filter_by(email=email).first():
        return {'Error': 'Email is already present'}
    
    if email is None:
        return {'Error': 'Please enter your email'}
    
    regex = re.compile(r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
    if not re.fullmatch(regex, email):
        return {'Error': 'Please enter a valid email'}
    
    if password is None or len(password) < 8:
        return {'Error': 'Password must be at least 8 characters long'}

    return None 
    

def send_mail(email):
    # breakpoint()
    msg = Message(
        'Hello', 
        sender ='manish@thoughtwin.com', 
        recipients = [email] 
        ) 
    msg.body = 'Hello Flask message sent from Flask-Mail'
    mail.send(msg) 
    return None

def send_mail_with_app_context(email):
    with app.app_context():
        send_mail(email)


class Hello(Resource): 
  
    def get(self,id=None): 
        if id is not None:
            user = User.query.filter_by(id=id).first()
            if user:
                return jsonify(user.to_dict())
            else:
                return jsonify({"msg":"User not found"})
        else:
            user = User.query.all()
            return jsonify([i.to_dict() for i in user]) 


    def post(self):
        data = request.get_json()
        validation_error = validate_user_data(data)
        if validation_error:
            return jsonify(validation_error)
    
        user = User(
            name=data['name'],
            username=data['username'],
            email=data['email'],
            password_hash=bcrypt.generate_password_hash(data['password_hash']).decode('utf-8')
        )
        t1 = threading.Thread(target=send_mail_with_app_context, args=(data['email'],))
        t1.start()
        db.session.add(user)
        db.session.commit()
        return jsonify({'data': 'User is created'})


    def delete(self,id):
        # breakpoint()
        user = User.query.filter_by(id=id).first()
        if user:
            db.session.delete(user)
            db.session.commit()
            return jsonify({'info':'data is deleted'})
        else:
            return jsonify({'msg':'User is not Present'})

    def put(self,id):
        # breakpoint()
        data = request.get_json()
        user = User.query.filter_by(id=id).first()
        if user:
            if 'username' in data:
                user.username = data['username']
                db.session.commit()
                return jsonify({'data':'updated'})
            if 'email' in data:
                user.email = data['email']
                db.session.commit()
                return jsonify({'data':'updated'})
            if 'name' in data:
                user.name = data['name']
                db.session.commit()
                return jsonify({'data':'updated'})
            else:
                return jsonify({'error':'Please updated proper field'})

class LoginView(Resource):
    def post(self):
        data = request.get_json()
        username = data['username']
        password = data['password_hash']
        print('Received data:', username , password)

        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password_hash, password):
            access_token = create_access_token(identity=user.id)
            return jsonify({'message': 'Login Success', 'access_token': access_token})
        else:
            return jsonify({'message': 'Login Failed'}), 401

    @jwt_required()
    def get(self):
        user_id = get_jwt_identity()
        user = User.query.filter_by(id=user_id).first()
        if user:
            return jsonify({'message': 'User found', 'name': user.name})
        else:
            return jsonify({'message': 'User not found'}), 404



            
api.add_resource(Hello,"/","/<int:id>", methods=['GET','POST','DELETE','PUT'])
api.add_resource(LoginView,"/login","/home",methods=['POST','GET'])
