import bcrypt
from datetime import datetime, timedelta
from jose import jwt, JWTError

SECRET_KEY = "CHANGE_ME_SECRET_KEY_123456"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_HOURS = 24

def hash_password(password: str) -> str:
    password = str(password).encode("utf-8")[:72]
    return bcrypt.hashpw(password, bcrypt.gensalt()).decode()
    
def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(
        str(password).encode("utf-8")[:72],
        hashed.encode("utf-8")
    )

def create_token(username: str) -> str:
    expire = datetime.utcnow() + timedelta(hours=ACCESS_TOKEN_EXPIRE_HOURS)
    payload = {"sub": username, "exp": expire}
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload.get("sub")
    except JWTError:
        return None
