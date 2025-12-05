import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

class Config:
    SECRET_KEY = "laposta-super-secret-key"

    SQLALCHEMY_DATABASE_URI = (
        "mysql+mysqlconnector://sql3810707:MLBQAFgGSP@sql3.freesqldatabase.com:3306/sql3810707"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    BASE_URL = "https://laposta-4neo.onrender.com"
