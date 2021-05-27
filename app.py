# flask imports
import os
import json
from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
import uuid  # for public id
from werkzeug.security import generate_password_hash, check_password_hash
# imports for PyJWT authentication
import jwt
from datetime import datetime, timedelta
from functools import wraps

DEBUG = os.environ.get('DEBUG')
if(DEBUG != None and DEBUG == 'True'):
    DEBUG = True
else:
    DEBUG = False

SECRET_KEY = os.environ.get('SECRET_KEY')
if(SECRET_KEY != None and SECRET_KEY == ''):
    pass
else:
    SECRET_KEY = 'yoursecretkey123789'


# creates Flask object
app = Flask(__name__)
# configuration
# NEVER HARDCODE YOUR CONFIGURATION IN YOUR CODE
# INSTEAD CREATE A .env FILE AND STORE IN IT
app.config['SECRET_KEY'] = SECRET_KEY


# database name
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
# creates SQLALCHEMY object
db = SQLAlchemy(app)


# Database ORMs
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    email = db.Column(db.String(70), unique=True)
    password = db.Column(db.String(80))


createDatabase = False
if not os.path.exists('Database.db'):
    print('Database not found')
    createDatabase = True

if createDatabase:
    try:
        # from app import db
        db.create_all()
    except SQLAlchemy.InvalidRequestError as err:
        print(err)
    except Exception as e:
        print(e)


# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']
        # if token is not passed
        if not token:
            return jsonify({'error_message': 'Access token is missing !!'}), 422
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(
                token, key=app.config['SECRET_KEY'], algorithms=['HS256'])
            current_user = User.query\
                .filter_by(public_id=data['public_id'])\
                .first()
        except jwt.ExpiredSignatureError:
            return jsonify({'error_message': 'Access token is Expired !!'}), 408
        except:
            return jsonify({'error_message': 'Access token is Invalid !!'}), 406
        # returns the current logged in users contex to the routes
        return f(current_user, *args, **kwargs)

    return decorated


# User Database Route
# this route sends back list of users users
@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):
    # querying the database for all the entries in it
    users = User.query.all()
    # converting the query objects to list of jsons
    output = []
    for user in users:
        # appending the user data json
        # to the response list
        output.append({
            'public_id': user.public_id,
            'name': user.name,
            'email': user.email
        })

    return jsonify({'users': output}), 200


# route for loging user in
@app.route('/login', methods=['POST'])
def login():
    # creates dictionary of form data
    auth = request.form
    # if any email and password is missing
    if not auth or not auth.get('email') or not auth.get('password'):
        return jsonify({'error_message': 'email and password is missing.'}), 422

    user = User.query\
        .filter_by(email=auth.get('email'))\
        .first()

    if not user:
        # if user does not exist
        return jsonify({'error_message': 'user does not exist.'}), 401

    if check_password_hash(user.password, auth.get('password')):
        # generates the JWT Token
        usertoken = {
            'public_id': user.public_id,
            'exp': datetime.utcnow() + timedelta(minutes=5)
        }
        userrefreshtoken = {
            'public_id': user.public_id,
            'exp': datetime.utcnow() + timedelta(minutes=60)
        }
        access_token = jwt.encode(
            usertoken, key=app.config['SECRET_KEY'], algorithm='HS256')
        refresh_token = jwt.encode(
            userrefreshtoken, key=app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 201
    # if password is wrong
    return jsonify({'error_message': 'password is wrong'}), 403


# user logout
@app.route('/refresh_token', methods=['GET'])
def refresh_token():
    # jwt is passed in the request header
    if 'x-refresh-token' in request.headers:
        refresh_token = request.headers['x-refresh-token']
    if not refresh_token:
        return jsonify({'error_message': 'Refresh token is missing !!'}), 422
    try:
        # decoding the payload to fetch the stored details
        data = jwt.decode(
            refresh_token, key=app.config['SECRET_KEY'], algorithms=['HS256'])
        current_user = User.query\
            .filter_by(public_id=data['public_id'])\
            .first()

        # generates the JWT Token
        usertoken = {
            'public_id': current_user.public_id,
            'exp': datetime.utcnow() + timedelta(minutes=5)
        }
        access_token = jwt.encode(
            usertoken, key=app.config['SECRET_KEY'], algorithm='HS256')
        # Genrate new refresh_token only if it's expired within upcoming min 4000 sec
        refresh_token_expired_min = data['exp'] - datetime.timestamp(datetime.utcnow())
        if(refresh_token_expired_min < 4000):
            userrefreshtoken = {
                'public_id': current_user.public_id,
                'exp': datetime.utcnow() + timedelta(minutes=60)
            }
            refresh_token = jwt.encode(
                userrefreshtoken, key=app.config['SECRET_KEY'], algorithm='HS256')
            return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 201
        else:
            return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 200
    except jwt.ExpiredSignatureError:
        return jsonify({'error_message': 'Refresh token is Expired !!'}), 408
    except:
        return jsonify({'error_message': 'Refresh token is Invalid !!'}), 406


# signup route
@app.route('/signup', methods=['POST'])
def signup():
    # creates a dictionary of the form data
    data = request.form
    # if email, name and password is missing
    if not data or not data.get('email') or not data.get('name') or not data.get('password'):
        return jsonify({'error_message': 'email, name and password is missing.'}), 422

    # gets name, email and password
    name, email = data.get('name'), data.get('email')
    password = data.get('password')

    # checking for existing user
    user = User.query\
        .filter_by(email=email)\
        .first()
    if not user:
        # database ORM object
        user = User(
            public_id=str(uuid.uuid4()),
            name=name,
            email=email,
            password=generate_password_hash(password)
        )
        # insert user
        db.session.add(user)
        db.session.commit()

        return jsonify({'message': 'Successfully registered.'}), 201
    else:
        # returns 202 if user already exists
        return jsonify({'message': 'User already exists. Please Log in.'}), 202


# Home
@app.route('/', methods=['GET'])
def home():
    data = {'message': 'Flask JWT oauth',
            'time': str(datetime.now().strftime("%c"))}
    if(DEBUG):
        data['env'] = dict(os.environ)
    return jsonify(data), 200


# Postman
@ app.route('/postman', methods=['GET'])
def postmanAPI():
    return json.load(open('jwtpython.postman_collection.json'))


# Error Handling
@ app.errorhandler(404)
def page_not_found(e):
    return jsonify({'error_message': str(e)}), 404


# Flask server invoke
if __name__ == "__main__":
    # setting debug to True enables hot reload
    # and also provides a debuger shell
    # if you hit an error while running the server
    app.run(debug=DEBUG, use_reloader=True)
