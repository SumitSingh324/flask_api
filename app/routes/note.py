from flask import Blueprint, jsonify
from app import app
from flask_restful import Resource,Api

note_bp = Blueprint('notes', __name__)
api = Api(app)

class One(Resource):
    def get(self,id=None):
        if id is None:
            return jsonify({'msg':'Hello'})
        else:
            return jsonify({"msg":f"Hello {id}"})
            

api.add_resource(One,'/one/',"/one/<int:id>",methods = ['GET'])
