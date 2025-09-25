from fastapi import HTTPException, Depends
import uuid
import bcrypt
from models.user import User
from pydantic_shcemas.user_create import UserCreate
from pydantic_shcemas.user_signin import UserSignIn
from fastapi import APIRouter
from database import get_db
from sqlalchemy.orm import Session


router = APIRouter()

@router.post("/signup", status_code=201)
def signup_user(user: UserCreate, db: Session = Depends(get_db)):
    
    #check if user already exists
    existing_user = db.query(User).filter(User.email == user.email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
        
    #create new user
    hashed_pwd = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt(16))
    new_user = User(
        id=str(uuid.uuid4()),
        name=user.name,
        email=user.email,
        password=hashed_pwd
    )
    #save user to db
    db.add(new_user)
    #commit the changes
    db.commit()
    #refresh the user instance
    db.refresh(new_user)
    #return the created user
    return new_user


@router.post("/signin")
def signin_user(user: UserSignIn, db: Session = Depends(get_db)):

    existing_user = db.query(User).filter(User.email == user.email).first()
    if not existing_user:
        raise HTTPException(status_code=400, detail="Invalid email or password")

    # Verify password (encode stored hash as bytes)
    is_match_password = bcrypt.checkpw(user.password.encode(), existing_user.password)

    if not is_match_password:
        raise HTTPException(status_code=400, detail="Invalid email or password")

    return existing_user

