from os import environ, path
from dotenv import load_dotenv
import os

basedir = path.abspath(path.dirname(__file__))
load_dotenv(path.join(basedir, '.env_dev'))

class Config:
    SECRET_KEY = environ.get('SECRET_KEY')
    PASS = environ.get('PASS')
    USERNAME = environ.get('USERNAME')
    SQLALCHEMY_DATABASE_URI = 'sqlite:///database.db'
    IMG_FOLDER = 'img'
    TEMPLATES_FOLDER = 'templates'