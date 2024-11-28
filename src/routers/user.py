from fastapi import APIRouter,HTTPException
from database.database import SessionLocal
from src.models.user import User,OTP
from src.schemas.user import RegisterUserSchema,GetAllUserSchema,UpdateUserSchema,ForgetPasswordSchema,ResetPasswordSchema
import uuid,random
from src.utils.user import pwd_context,find_same_username,find_same_email,send_email,pass_checker,get_token,gen_otp

user_router=APIRouter()
db=SessionLocal()

@user_router.post("/register_user")
def register_user(user:RegisterUserSchema):
    new_user=User(id=str(uuid.uuid4()),username=user.username,email=user.email,password=pwd_context.hash(user.password))
    
    find_minimum_one_entry=db.query(User).first()
    if find_minimum_one_entry:
        find_same_username(user.username)
        find_same_email(user.email)
        
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return "User register successfully now go for verification"




@user_router.post("/generate otp")
def generate_otp(email:str):
    gen_otp(email)
    return generate_otp



@user_router.get("/verify_otp")
def verify_otp(email:str,otp:str):
    find_user_with_email=db.query(User).filter(User.email == email,User.is_active == True,User.is_verified == False,User.is_deleted==False).first()
    
    if not find_user_with_email:
        raise HTTPException(status_code=400,detail="User not found")
    
    find_otp=db.query(OTP).filter(OTP.email == email, OTP.otp == otp).first()
    
    if not find_otp:
        raise HTTPException(status_code=400,detail="OTP not found")
    
    find_user_with_email.is_verified = True
    db.delete(find_otp)
    db.commit()
    db.refresh(find_user_with_email)
    return "OTP verified successfully"




@user_router.get("/login_user")
def login_user(email:str,password:str):
    find_user=db.query(User).filter(User.email == email,User.is_active==True,User.is_verified==True,User.is_deleted==False).first()
    
    if not find_user:
        raise HTTPException(status_code=400,detail="User not found")
    
    pass_checker(password,find_user.password) 
    
    access_token= get_token(find_user.id,find_user.username,find_user.email)

    return access_token, "Login successfully"




@user_router.get("/get_user/{user_id}",response_model=GetAllUserSchema)
def get_user(user_id:str):
    
    find_user=db.query(User).filter(User.id == user_id,User.is_active==True, User.is_verified==True, User.is_deleted==False).first()
    
    if not find_user:
        raise HTTPException(status_code=400,detail="User not found")
    
    return find_user




@user_router.get("/get_all_user",response_model=list[GetAllUserSchema])
def get_all_user():
    
    find_all_user=db.query(User).filter(User.is_active == True,User.is_verified == True,User.is_deleted == False).all()
    
    if not find_all_user:
        raise HTTPException(status_code=400,detail="User not found")
    
    return find_all_user




@user_router.patch("/update_user/{user_id}") 
def update_user(user_id:str,user:UpdateUserSchema):
    
    find_user = db.query(User).filter(User.id == user_id,User.is_active==True,User.is_verified==True,User.is_deleted==False).first()
    
    if not find_user:
        raise HTTPException(status_code=400,detail="User not found")
    
    new_userschema_without_none=user.model_dump(exclude_none=True)
    
    for key,value in new_userschema_without_none.items():
        if key == "password":
            setattr(find_user,key,pwd_context.hash(value))
        else:
            find_same_email(value)
            find_same_username(value)
            setattr(find_user,key,value)
            
    db.commit()
    db.refresh(find_user)
    return {"message": "User updated successfully", "data":find_user}




@user_router.delete("/delete_user/{user_id}")
def delete_user(user_id:str):
    
    find_user=db.query(User).filter(User.id == user_id,User.is_active==True,User.is_verified==True).first()
    
    if not find_user:
        raise HTTPException(status_code=400,detail="User not found")
    
    if find_user.is_deleted==True:
        raise HTTPException(status_code=400,detail="User account already deleted")
    
    find_user.is_deleted=True
    find_user.is_active=False
    find_user.is_verified=False
    db.commit()
    db.refresh(find_user)
    return {"message" : "User deleted successfully", "data" : find_user}




@user_router.post("/generate_otp_for_forget_password")
def generate_otp_for_forget_password(email:str):
    gen_otp(email)
    return "OTP send successfully"




@user_router.patch("/forget_password")
def forget_password(email:str,otp:str,user:ForgetPasswordSchema):
    
    find_user=db.query(User).filter(User.email == email,User.is_active == True,User.is_verified == True,User.is_deleted == False).first()
    
    if not find_user:
        raise HTTPException(status_code=400,detail="User not found")
    
    find_otp=db.query(OTP).filter(OTP.email == email,OTP.otp == otp).first()
    
    if not find_otp:
        raise HTTPException(status_code=400,detail="OTP not found")
    
    if user.new_password == user.confirm_password:
        setattr(find_user,"password" ,pwd_context.hash(user.confirm_password))
    else:
        raise HTTPException(status_code=400, detail="Password confirmation does not match new password")
    
    db.delete(find_otp)
    db.commit()
    db.refresh(find_user)
    
    return "password changed successfully"



@user_router.patch("/reset_password")
def reset_password(email:str,user:ResetPasswordSchema):
    
    find_user=db.query(User).filter(User.email == email,User.is_active == True, User.is_verified == True,User.is_deleted == False).first()
    
    if not find_user:
        raise HTTPException(status_code=400,detail="User not found")
    
    pass_checker(user.old_password,find_user.password)
    
    if user.new_password == user.confirm_password:
        setattr(find_user,"password" ,pwd_context.hash(user.confirm_password))
    else:
        raise HTTPException(status_code=400, detail="Password confirmation does not match new password")
    
    db.commit()
    db.refresh(find_user)
    
    return "Password reset successfully"