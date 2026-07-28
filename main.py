from datetime import datetime
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordRequestForm
from sqlmodel import Session, select

from database.session import create_db_and_tables, get_session
from models.user import User, UserCreate, UserResponse, UserUpdate
from models.patient import Patient
from auth import (
    hash_password,
    verify_password,
    create_access_token,
    get_current_user,
    get_current_active_user,
    get_current_doctor,
    get_current_admin,
)

app = FastAPI(title="HealthTrack API", version="1.0.0")


@app.on_event("startup")
def on_startup():
    create_db_and_tables()


@app.get("/")
def root():
    return {"message": "Welcome to HealthTrack API", "docs": "/docs"}


@app.post("/register", response_model=UserResponse, status_code=201)
def register_user(user_data: UserCreate, session: Session = Depends(get_session)):
    existing_username = session.exec(
        select(User).where(User.username == user_data.username)
    ).first()

    if existing_username:
        raise HTTPException(status_code=409, detail="Username already exists")

    existing_email = session.exec(
        select(User).where(User.email == user_data.email)
    ).first()

    if existing_email:
        raise HTTPException(status_code=409, detail="Email already exists")

    user = User(
        username=user_data.username,
        email=user_data.email,
        hashed_password=hash_password(user_data.password),
        full_name=user_data.full_name,
        role=user_data.role,
    )

    session.add(user)
    session.commit()
    session.refresh(user)

    return user


@app.post("/login")
def login_user(
    form_data: OAuth2PasswordRequestForm = Depends(),
    session: Session = Depends(get_session),
):
    user = session.exec(
        select(User).where(User.username == form_data.username)
    ).first()

    if not user or not verify_password(
        form_data.password,
        user.hashed_password,
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    user.last_login = datetime.utcnow()
    session.add(user)
    session.commit()

    access_token = create_access_token(
        data={"sub": user.username}
    )

    return {
        "access_token": access_token,
        "token_type": "bearer",
    }


@app.post("/logout")
def logout_user(current_user: User = Depends(get_current_user)):
    return {"message": "Logged out successfully"}


@app.get("/users/me", response_model=UserResponse)
def get_current_user_profile(
    current_user: User = Depends(get_current_active_user),
):
    return current_user


@app.put("/users/me", response_model=UserResponse)
def update_current_user_profile(
    user_update: UserUpdate,
    current_user: User = Depends(get_current_active_user),
    session: Session = Depends(get_session),
):
    if user_update.email is not None:
        current_user.email = user_update.email

    if user_update.full_name is not None:
        current_user.full_name = user_update.full_name

    current_user.updated_at = datetime.utcnow()

    session.add(current_user)
    session.commit()
    session.refresh(current_user)

    return current_user


@app.get("/users", response_model=list[UserResponse])
def list_users(
    skip: int = 0,
    limit: int = 10,
    role: Optional[str] = None,
    current_user: User = Depends(get_current_admin),
    session: Session = Depends(get_session),
):
    query = select(User)

    if role:
        query = query.where(User.role == role)

    users = session.exec(
        query.offset(skip).limit(limit)
    ).all()

    return users


@app.get("/patients")
def get_patients(
    current_user: User = Depends(get_current_doctor),
    session: Session = Depends(get_session),
):
    patients = session.exec(select(Patient)).all()
    return patients


@app.get("/patients/{patient_id}")
def get_patient(
    patient_id: int,
    current_user: User = Depends(get_current_user),
    session: Session = Depends(get_session),
):
    patient = session.get(Patient, patient_id)

    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")

    if (
        current_user.role != "admin"
        and patient.user_id != current_user.id
        and patient.doctor_id != current_user.id
    ):
        raise HTTPException(status_code=403, detail="Access denied")

    return patient


@app.post("/forgot-password")
def forgot_password(
    email: str,
    session: Session = Depends(get_session),
):
    user = session.exec(
        select(User).where(User.email == email)
    ).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    reset_token = create_access_token(
        data={"sub": user.username},
    )

    return {
        "message": "Reset token generated",
        "reset_token": reset_token,
    }


@app.post("/reset-password")
def reset_password(
    token: str,
    new_password: str,
    session: Session = Depends(get_session),
):
    from auth import decode_access_token

    username = decode_access_token(token)

    if username is None:
        raise HTTPException(status_code=400, detail="Invalid or expired token")

    user = session.exec(
        select(User).where(User.username == username)
    ).first()

    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    user.hashed_password = hash_password(new_password)
    user.updated_at = datetime.utcnow()

    session.add(user)
    session.commit()

    return {"message": "Password reset successful"}