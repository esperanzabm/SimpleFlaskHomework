from flask_pymongo import PyMongo

def init_mongo(app):
    return PyMongo(app)