from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import os
from flask_mail import Mail, Message

# from .models import *

app = Flask(__name__)
app.config['SECRET_KEY']='thisissecretkey'



app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app,db)

mail = Mail(app)
app.config['MAIL_SERVER']='smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'manish@thoughtwin.com'
app.config['MAIL_PASSWORD'] = 'xpdd stad tfjw lush'
app.config['MAIL_USE_TLS'] = True

mail = Mail(app) 

app.config['SECURITY_PASSWORD_SALT']='sumit@123'

from .routes import user_bp, note_bp
app.register_blueprint(user_bp)
app.register_blueprint(note_bp)