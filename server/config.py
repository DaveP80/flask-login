from os import environ, path
from dotenv import load_dotenv
import os

basedir = path.abspath(path.dirname(__file__))
load_dotenv(path.join(basedir, '.env'))

class Config:
    SECRET_KEY = environ.get('SECRET_KEY')
    PASS = environ.get('PASS')
    USERNAME = environ.get('USERNAME')
    ADMIN = environ.get('ADMIN')
    SQLALCHEMY_DATABASE_URI = environ.get('SQLALCHEMY_DATABASE_URI')
    URL = environ.get('URL')
    IMG_FOLDER = 'img'
    TEMPLATES_FOLDER = 'templates'