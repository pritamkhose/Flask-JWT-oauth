import uuid  # for public id
from werkzeug.security import generate_password_hash, check_password_hash
# imports for PyJWT authentication
import jwt
from datetime import datetime, timedelta

# data = {'some': 'payload', 'date': str(datetime.utcnow())}
SECRET_KEY = 'yoursecretkey2532634754854895'
# # print(SECRET_KEY, data)

# encoded = jwt.encode(data, SECRET_KEY, algorithm='HS256')
# print(encoded)
# decodeVal = jwt.decode(encoded, SECRET_KEY, algorithms='HS256')
# print(decodeVal)
# print(datetime.utcnow() , timedelta(minutes=1))


myjwt = {
    'public_id': 'db5a07b4-a4b0-4c67-974a-8c0d27ba2e2c', #user.public_id,
    'exp': (datetime.utcnow() + timedelta(minutes=1))
}
print(myjwt)
encoded = jwt.encode(myjwt, key=SECRET_KEY, algorithm='HS256')
# print(SECRET_KEY, encoded)
# oldtoken = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwdWJsaWNfaWQiOiJkYjVhMDdiNC1hNGIwLTRjNjctOTc0YS04YzBkMjdiYTJlMmMiLCJleHAiOjE2MjA2NTgyMDd9.MBuFCxBZGbMct0P3zi6OC-zKPD9CSZGoW1H-ieVyQ2k'
# encoded = 'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJwdWJsaWNfaWQiOiJkYjVhMDdiNC1hNGIwLTRjNjctOTc0YS04YzBkMjdiYTJlMmMiLCJleHAiOjE2MjIwNDk1NzB9.a0e7BKOfksYFy9mBn5q6HFrkHhXz_NWyEHuyWN8Ig6U'
# print(encoded)
try:
    decodeVal = jwt.decode(encoded, key=SECRET_KEY, algorithms=['HS256'])
    print(decodeVal)
except jwt.ExpiredSignatureError:
    print("Signature has expired!")
except:
    print("Something else went wrong") 

