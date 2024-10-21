from flask import Flask
import os

app = Flask(__name__)

DEBUG = True


# Set environment variable
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = ''

class Config:
    app.config['WTF_CSRF_ENABLED'] = False
    app.config['SESSION_TYPE'] = 'filesystem'