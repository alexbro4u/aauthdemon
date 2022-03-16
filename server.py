
#commit
import base64
import hmac
import hashlib

from typing import Optional

from fastapi import FastAPI, Cookie, Body, Forms
from fastapi.responses import Response

import json

app = FastAPI()

PASSWORD_SALT = "788161556bfa5a51b1ed069c34efed434b42df1cbb2708edb2cae60da11310eb"
SECRET_KEY = "5a34e717d5bfb93956444fb0129ae7811a958782f3c1c14c3177fab6fb60294d"


def sign_data(data:str) -> str:
    """Returns signed data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


def get_username_from_signed_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    if hmac.compare_digest(valid_sign,sign):
        return username

def verify_password(username: str, password: str) -> bool:
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username] ["password"].lower()
    return password_hash == stored_password_hash

users = {
    "Alexander@user.com": {
        "name": "Alexander",
        "password": "86c2a5ae3e580575c3d404ab30015a36b04c5ec8222e4a14301724566527b09f",
        "balance": 100_000
    }, 
    "mikhail@user.com": {
        "name": "Mikhail",
        "password": "4ec06481c96f20b90e26c79408d00401ceb1fb00859239463bcafadf1f7ece44",
        "balance": 555_555
    }
}

@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html','r') as f:
        login_page = f.read()
    
    if not username:
        return Response(login_page,media_type="text/html")

    
    valid_username = get_username_from_signed_string(username)
   
   
    if not valid_username:
        response = Response(login_page,media_type="text/html")
        response.delete_cookie(key="username")
        return response

    try:
        user = users[valid_username] 
    except KeyError:
        response = Response(login_page,media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(
        f"Hello, {users[valid_username]['name']}!<br/>"
        f"Balance:{users[valid_username]['balance']}",
        media_type="text/html")    
   


@app.post("/login")
def process_login_page(username: str = Form(...), password: str = Form(...)):
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response( 
            json.dumps({ 
                "success": False, 
                "message": "Incorrect password or username"
            }),
            media_type="application/json")

    response = Response(
        json.dumps({
            "success": True,
            "message": f"Hello, {user['name']}!<br/>Balance: {user['balance']}"
        }),
        media_type="application/json")

    username_signed = base64.b64encode(username.encode()).decode()+ "." +\
    sign_data(username)
    response.set_cookie(key="username",value=username_signed)
    return response



