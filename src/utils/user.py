from passlib.context import CryptContext
from database.database import SessionLocal
from src.models.user import User,OTP
from fastapi import HTTPException
import random,uuid

db=SessionLocal()


pwd_context=CryptContext(schemes=["bcrypt"],deprecated="auto")

def find_same_username(username:str):
    find_same_username=(
        db.query(User)
        .filter(User.username == username and User.is_active == True)
        .first()
    )

    if find_same_username:
        if find_same_username.is_active == True:
            raise HTTPException(status_code=400,detail="Username already exists")
        if find_same_username.is_active == False:
            raise HTTPException(status_code=400,detail="Username already exists but this account is deleted try with different username")
        
def find_same_email(email:str):
    find_same_email=(
        db.query(User)
        .filter(User.email == email and User.is_active == True)
        .first()
    )
    
    if find_same_email:
        if find_same_email.is_active == True:
            raise HTTPException(status_code=400,detail="Email already exists")
        if find_same_email.is_active == False:
            raise HTTPException(status_code=400,detail="Email already exists but this account is deleted try with different username")
        
        
#----------------------------------------------------------------------------------------------------
#otp generate

def gen_otp(email):
    
    find_user=(db.query(User).filter(User.email == email,User.is_active == True,User.is_deleted == False).first())
    
    if not find_user:
        raise HTTPException(status_code=400,detail="User not found")    
    
    random_otp=random.randint(1000,9999)
    print("----")
    print(random_otp)
    print("----")
    
    #database ma otp store thase aanathi
    new_otp=OTP(id=str(uuid.uuid4()),email=find_user.email,user_id=find_user.id,otp=random_otp)
    
    send_email(find_user.email, "Test Email", f"Otp is {random_otp}")
    
    
    db.add(new_otp)
    db.commit()
    db.refresh(new_otp)
    return "OTP generated successfully"



        
#----------------------------------------------------------------------------------------------------        

import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from config import SENDER_EMAIL, EMAIL_PASSWORD


def send_email(receiver, subject, body):

    smtp_server = "smtp.gmail.com"
    smtp_port = 587
    smtp_user = SENDER_EMAIL
    smtp_pass = EMAIL_PASSWORD

    msg = MIMEMultipart()
    msg["From"] = SENDER_EMAIL
    msg["To"] = receiver
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))


    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(smtp_user, smtp_pass)
            server.sendmail(SENDER_EMAIL, receiver, msg.as_string())
        print("Email sent successfully!")
    except Exception as e:
        print(f"Error: {e}")


def pass_checker(user_pass,hash_pass):
    if pwd_context.verify(user_pass,hash_pass):
        return True
    else:
        raise HTTPException(status_code=401,detail="Password is incorrect")
    
#--------------------------------------------------------------------------------------

from config import SECRET_KEY, ALGORITHM
from datetime import datetime, timedelta, timezone
import jwt
from fastapi import HTTPException, status


def get_token(id: str, username: str, email: str):

    payload = {
        "id": id,
        "username": username,
        "email": email,
        "exp": datetime.now(timezone.utc) + timedelta(seconds=30)
    }

    access_token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return {"access_token": access_token}

def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        id = payload.get("id")
        email = payload.get("email")
        username = payload.get("username")
        if not id or not username or not email:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Invalid token")
        return id, username, email

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Token has expired",
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Invalid token",
        )
        
        
        