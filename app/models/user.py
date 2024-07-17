from app import db
from datetime import datetime
from sqlalchemy.orm import validates

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def to_dict(self):
        return {"id":self.id, "name":self.name, "username":self.username, "email":self.email, "created_at":self.created_at}

    def __repr__(self):
        return f'<User {self.username}>'

    @validates('username')
    def validate_username(self, key, value):
        if not value:
            raise ValueError("Must have a username")
        return value



