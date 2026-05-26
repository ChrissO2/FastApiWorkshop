from fastapi import FastAPI, HTTPException, Depends
from fastapi import security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from auth import create_access_token, verify_token


class RegisterRequest(BaseModel):
    username: str
    password: str


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str


class User(BaseModel):
    id: int
    username: str
    password: str


app = FastAPI()

security = HTTPBearer()

users_db = []

@app.post("/register")
def register(data: RegisterRequest):
    for user in users_db:
        if user.username == data.username:
            raise HTTPException(
                status_code=400,
                detail="User already exists"
            )
    user = User(
        id=len(users_db) + 1,
        username=data.username,
        password=data.password
    )
    users_db.append(user)

    return {"msg": "User created"}


@app.post("/login", response_model=TokenResponse)
def login(data: LoginRequest):
    for user in users_db:
        if user.username == data.username and user.password == data.password:
            access_token = create_access_token({"sub": user.username})
            return {
                "access_token": access_token,
                "refresh_token": "temporary",
                "token_type": "bearer"
            }
    raise HTTPException(status_code=401, detail="Invalid credentials")


@app.post("/refresh")
def refresh():
    return {"message": "refresh endpoint"}


@app.get("/me")
def me(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = verify_token(token)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid token")
    return {
        "username": payload.get("sub")
    }
