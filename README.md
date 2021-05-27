# JWT Token Auth Python

Secure a Flask REST API with JSON Web Token also deploy on heroku.

# Install dependecies

```sh
python --version

pip install -r requirements.txt
```

# Run server

```sh
python app.py
```

You should be able to run this app on your own system via the familiar invocation and visiting [http://localhost:5000](http://localhost:5000).

## Set env config variable

| name       | Description                | e.g.                                                                         |
| ---------- | -------------------------- | ---------------------------------------------------------------------------- |
| DEBUG      | Run flask development-mode | True or False                                                                |
| FLASK_ENV  | Run flask enviorment-mode  | development                                                                  |
| TZ         | Time zone of server        | Asia/Calcutta                                                                |
| SECRET_KEY | JWT app SECRET_KEY         | yoursecretkey123789                                                          |
| MONGOURL   | mongo db server url        | mongodb://usename:password@serverurl:27017/MONGODB?ssl=true&retryWrites=true |
| MONGODB    | mongo database name        |                                                                              |

# References

- [Related Article](https://www.geeksforgeeks.org/using-jwt-for-user-authentication-in-flask/)

- [PyJWT](https://pypi.org/project/PyJWT/)

- [Flask-JWT-Extended](https://flask-jwt-extended.readthedocs.io/en/stable/refreshing_tokens/) [PIP](https://pypi.org/project/Flask-JWT-Extended/)

- [logot jwt](https://github.com/vimalloc/flask-jwt-extended/blob/master/examples/blocklist_database.py)

- [Jwt.io](https://jwt.io/)

- [Stackoverflow sqlalchemy](https://stackoverflow.com/questions/20744277/sqlalchemy-create-all-does-not-create-tables)
