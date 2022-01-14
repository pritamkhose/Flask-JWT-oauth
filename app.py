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


class SessionLogout(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_type = db.Column(db.String(20))
    session_id = db.Column(db.String(255))


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
        access_token = request.headers.get('x-access-token')
        # if access token is not passed
        if access_token != None and access_token != '':
            try:
                # decoding the payload to fetch the stored details
                data = jwt.decode(
                    access_token, key=app.config['SECRET_KEY'], algorithms=['HS256'])
                current_user = User.query\
                    .filter_by(public_id=data['public_id'])\
                    .first()
                # # add access_token to blocklist if need or it will exipry after 5 min
                # session = SessionLogout.query.filter_by(session_id=access_token).all()
                # if session != None and len(session) > 0:
                #     return jsonify({'error_message': 'you have been logout. Please login again!'}), 408
                # returns the current logged in users contex to the routes
                return f(current_user, *args, **kwargs)
            except jwt.ExpiredSignatureError:
                return jsonify({'error_message': 'Access token is Expired !!'}), 408
            except:
                return jsonify({'error_message': 'Access token is Invalid !!'}), 406
        else:
            return jsonify({'error_message': 'Access token is missing !!'}), 422
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
    auth = request.json
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
        iat = datetime.utcnow()
        usertoken = {
            'public_id': user.public_id,
            'exp': iat + timedelta(minutes=5),
            'iat': iat
        }
        userrefreshtoken = {
            'public_id': user.public_id,
            'exp': iat + timedelta(minutes=60),
            'iat': iat
        }
        access_token = jwt.encode(
            usertoken, key=app.config['SECRET_KEY'], algorithm='HS256')
        refresh_token = jwt.encode(
            userrefreshtoken, key=app.config['SECRET_KEY'], algorithm='HS256')
        return jsonify({'access_token': access_token, 'refresh_token': refresh_token}), 201
    # if password is wrong
    return jsonify({'error_message': 'password is wrong'}), 403


# user refresh_token
@app.route('/refresh_token', methods=['GET'])
def refresh_token():
    # jwt is passed in the request header
    refresh_token = request.headers.get('x-refresh-token')
    if refresh_token != None and refresh_token != '':
        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(
                refresh_token, key=app.config['SECRET_KEY'], algorithms=['HS256'])
            # checking for existing session_id is logout
            session = SessionLogout.query\
                .filter_by(session_id=refresh_token).all()
            # output = []
            # for ses in session:
            #     output.append({
            #         'id': ses.id,
            #         'session_type': ses.session_type,
            #         'session_id': ses.session_id
            #     })
            if session != None and len(session) > 0:
                # , 'session': output
                return jsonify({'error_message': 'you have been logout. Please login again!'}), 408
            else:
                current_user = User.query\
                    .filter_by(public_id=data['public_id'])\
                    .first()

                # generates the JWT Token
                iat = datetime.utcnow()
                usertoken = {
                    'public_id': current_user.public_id,
                    'exp': iat + timedelta(minutes=5),
                    'iat': iat
                }
                access_token = jwt.encode(
                    usertoken, key=app.config['SECRET_KEY'], algorithm='HS256')
                # Genrate new refresh_token only if it's expired within upcoming min 4000 sec
                refresh_token_expired_min = data['exp'] - \
                    datetime.timestamp(iat)
                if(refresh_token_expired_min < 4000):
                    userrefreshtoken = {
                        'public_id': current_user.public_id,
                        'exp': iat + timedelta(minutes=60),
                        'iat': iat
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
    else:
        return jsonify({'error_message': 'Refresh token is missing !!'}), 422


# Logout
@app.route('/logout', methods=['GET'])
def logout_token():
    # jwt is passed in the request header
    access_token = request.headers.get('x-access-token')
    refresh_token = request.headers.get('x-refresh-token')
    if access_token != None and access_token != '' and refresh_token != None and refresh_token != '':
        try:
            # generates the JWT Token
            iat = datetime.utcnow()
            # decoding the payload to fetch the stored details
            data = jwt.decode(
                refresh_token, key=app.config['SECRET_KEY'], algorithms=['HS256'])
            # Genrate new refresh_token only if it's expired within upcoming min 4000 sec
            refresh_token_expired_min = data['exp'] - \
                   datetime.timestamp(iat)
            if(refresh_token_expired_min > 4000):
                # insert session_id in block list
                db.session.add(SessionLogout(
                    session_id=refresh_token, session_type='refresh_token'))
                # add access_token to blocklist if need or it will exipry after 5 min
                # db.session.add(SessionLogout(
                #     session_id=access_token, session_type='access_token'))
                db.session.commit()
                return jsonify({'message': 'You have been logout!', 'iat': iat}), 200
            else :
                return jsonify({'error_message': 'Refresh token is Expired !!', 'r': refresh_token_expired_min}), 408
        except jwt.ExpiredSignatureError:
            return jsonify({'error_message': 'Refresh token is Expired !!'}), 408
        except Exception as e:
            return jsonify({'error_message': str(e)}), 500
    else:
        return jsonify({'error_message': 'access and refresh token is missing !!'}), 422


# signup route
@app.route('/signup', methods=['POST'])
def signup():
    # creates a dictionary of the form data
    content = request.json
    # gets name, email and password
    name, email = content.get('name'), content.get('email')
    password = content.get('password')
    # if email, name and password is missing
    if (content != None and content != '' and type(content) == dict and name != None and name != ''
            and password != None and password != '' and email != None and email != ''):
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
    else:
        return jsonify({'error_message': 'email, name and password is missing.'}), 422


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
