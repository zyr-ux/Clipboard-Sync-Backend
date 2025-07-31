from fastapi import FastAPI, Depends, HTTPException, status
from sqlalchemy.orm import Session
from database import SessionLocal, engine, Base
from models import User
from schemas import UserCreate, UserLogin, Token, UserRegisterWithDevice, UserLoginWithDevice, SessionInfo
from auth import hash_password, verify_password, create_access_token
from schemas import DeviceRegister, DeviceOut
from auth import get_current_user
from models import Device
from typing import List
from crypto_utils import encrypt_clipboard, decrypt_clipboard, encrypt_token, decrypt_token
from models import Clipboard, EncryptionKey
from schemas import ClipboardIn, ClipboardOut
from schemas import ClipboardOutList
from datetime import timedelta, datetime
from secrets import token_urlsafe
from models import RefreshToken
from fastapi import Body
from fastapi import WebSocket, WebSocketDisconnect, HTTPException
from auth import get_user_from_token_ws
from collections import defaultdict
from jose import JWTError, jwt
import asyncio
from typing import Dict, List
from Crypto.Random import get_random_bytes
from models import BlacklistedToken
from auth import SECRET_KEY, ALGORITHM
from fastapi.security import OAuth2PasswordBearer
from connection_manager import ConnectionManager

ALLOW_AUTO_DEVICE_REGISTRATION = True  #Turn this off in production!

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# In-memory store: user_id -> list of WebSockets
active_connections = defaultdict(list)

ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 30

Base.metadata.create_all(bind=engine)
app = FastAPI()

manager = ConnectionManager()

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def cleanup_old_clipboard_entries(user_id: int, db: Session):
    one_week_ago = datetime.utcnow() - timedelta(days=7)
    db.query(Clipboard).filter(
        Clipboard.user_id == user_id,
        Clipboard.timestamp < one_week_ago
    ).delete()
    db.commit()

@app.post("/register", response_model=Token)
def register(user: UserRegisterWithDevice, db: Session = Depends(get_db)):
    # Check if email already exists
    if db.query(User).filter(User.email == user.email).first():
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    new_user = User(email=user.email, hashed_password=hash_password(user.password))
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    # Register device
    existing_device = db.query(Device).filter(Device.device_id == user.device_id).first()
    if not existing_device:
        new_device = Device(
            device_id=user.device_id,
            device_name=user.device_name,
            user_id=new_user.id
        )
        db.add(new_device)
        db.commit()

    # Create access token with device_id
    access_token = create_access_token(
        data={"sub": new_user.email, "device_id": user.device_id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    # Create refresh token
    plain_refresh_token = token_urlsafe(64)
    encrypted_refresh_token = encrypt_token(plain_refresh_token)
    refresh_expiry = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    db.add(RefreshToken(
        user_id=new_user.id,
        token=encrypted_refresh_token,
        expiry=refresh_expiry,
        device_id=user.device_id
    ))
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": plain_refresh_token,
        "token_type": "bearer"
    }

# Login route
@app.post("/login", response_model=Token)
def login(user: UserLoginWithDevice, db: Session = Depends(get_db)):
    db_user = db.query(User).filter(User.email == user.email).first()
    if not db_user or not verify_password(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    # Check if device is registered for this user
    device = db.query(Device).filter_by(device_id=user.device_id, user_id=db_user.id).first()
    if not device:
        if ALLOW_AUTO_DEVICE_REGISTRATION:
            device = Device(
                device_id=user.device_id,
                device_name=user.device_name or "Dev Device",
                user_id=db_user.id
            )
            db.add(device)
            db.commit()
            db.refresh(device)
        else:
            raise HTTPException(status_code=403, detail="Unregistered device")

    access_token = create_access_token(
        data={"sub": user.email, "device_id": device.device_id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    plain_refresh_token = token_urlsafe(64)
    encrypted_refresh_token = encrypt_token(plain_refresh_token)
    refresh_expiry = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    db.add(RefreshToken(
        user_id=db_user.id, 
        token=encrypted_refresh_token, 
        expiry=refresh_expiry,
        device_id=user.device_id
        ))
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": plain_refresh_token,
        "token_type": "bearer"
    }

@app.post("/devices/register", response_model=DeviceOut)
def register_device(
    device: DeviceRegister,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    existing = db.query(Device).filter(Device.device_id == device.device_id).first()
    if existing:
        return existing
    new_device = Device(
        device_id=device.device_id,
        device_name=device.device_name,
        user_id=current_user.id
    )
    db.add(new_device)
    db.commit()
    db.refresh(new_device)
    return new_device

@app.get("/devices", response_model=List[DeviceOut])
def get_devices(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    return db.query(Device).filter(Device.user_id == current_user.id).all()


@app.post("/clipboard")
def sync_clipboard(
    data: ClipboardIn,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    key_entry = db.query(EncryptionKey).filter_by(user_id=current_user.id).first()
    if not key_entry:
        from Crypto.Random import get_random_bytes
        key_entry = EncryptionKey(user_id=current_user.id, key=get_random_bytes(32))
        db.add(key_entry)
        db.commit()
        db.refresh(key_entry)

    encrypted_data, nonce = encrypt_clipboard(data.text, key_entry.key)

    new_entry = Clipboard(
        user_id=current_user.id,
        encrypted_data=encrypted_data,
        nonce=nonce
    )
    db.add(new_entry)
    db.commit()

    return {"status": "clipboard synced"}


@app.get("/clipboard", response_model=ClipboardOut)
def get_clipboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    cleanup_old_clipboard_entries(current_user.id, db)

    entry = (
        db.query(Clipboard)
        .filter_by(user_id=current_user.id)
        .order_by(Clipboard.timestamp.desc())
        .first()
    )
    key_entry = db.query(EncryptionKey).filter_by(user_id=current_user.id).first()

    if not entry or not key_entry:
        raise HTTPException(status_code=404, detail="No clipboard found")

    try:
        text = decrypt_clipboard(entry.encrypted_data, key_entry.key)
        return {
                "text": text,
                "timestamp": entry.timestamp
                }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption error: {str(e)}")

@app.get("/clipboard/all", response_model=ClipboardOutList)
def get_clipboard_history(
    page: int = 1,
    limit: int = 50,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    cleanup_old_clipboard_entries(current_user.id, db)

    key_entry = db.query(EncryptionKey).filter_by(user_id=current_user.id).first()
    if not key_entry:
        raise HTTPException(status_code=404, detail="Encryption key not found")

    # Calculate offset for pagination
    offset = (page - 1) * limit

    entries = (
        db.query(Clipboard)
        .filter_by(user_id=current_user.id)
        .order_by(Clipboard.timestamp.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )

    decrypted = []
    for entry in entries:
        try:
            text = decrypt_clipboard(entry.encrypted_data, key_entry.key)
            decrypted.append({
                "text": text,
                "timestamp": entry.timestamp
            })
        except Exception:
            continue  # skip corrupted entries

    return {"history": decrypted}

@app.post("/logout")
def logout(
    refresh_token: str = Body(...),
    access_token: str = Depends(oauth2_scheme),  # Access token comes from Authorization header
    db: Session = Depends(get_db)
):
    # Step 1: Blacklist the access token
    try:
        payload = jwt.decode(access_token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = payload.get("exp")
        if not exp:
            raise HTTPException(status_code=400, detail="Invalid token")

        db.add(BlacklistedToken(token=access_token, expiry=datetime.utcfromtimestamp(exp)))

    except jwt.JWTError:
        raise HTTPException(status_code=401, detail="Invalid access token")

    # Step 2: Delete the refresh token
    encrypted_refresh = encrypt_token(refresh_token)
    db.query(RefreshToken).filter(RefreshToken.token == encrypted_refresh).delete()

    db.commit()
    return {"message": "Logged out successfully"}


@app.post("/refresh", response_model=Token)
def refresh_token(
    refresh_token: str = Body(...),
    db: Session = Depends(get_db)
):
    encrypted_input_token = encrypt_token(refresh_token)
    token_entry = db.query(RefreshToken).filter(RefreshToken.token == encrypted_input_token).first()
    if not token_entry or token_entry.expiry < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token")

    db.delete(token_entry)
    db.commit()

    user = db.query(User).filter(User.id == token_entry.user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    access_token = create_access_token(
        data={"sub": user.email, "device_id": device.device_id},
        expires_delta=timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )

    new_plain_refresh_token = token_urlsafe(64)
    encrypted_refresh_token = encrypt_token(new_plain_refresh_token)
    refresh_expiry = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    db.add(RefreshToken(
        user_id=user.id,
        token=encrypted_refresh_token,
        expiry=refresh_expiry,
        device_id=user.device_id
    ))
    db.commit()

    return {
        "access_token": access_token,
        "refresh_token": new_plain_refresh_token,
        "token_type": "bearer"
    }

def delete_account(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Delete user's clipboard data
    db.query(Clipboard).filter_by(user_id=current_user.id).delete()

    # Delete user's devices
    db.query(Device).filter_by(user_id=current_user.id).delete()

    # Delete user's encryption key
    db.query(EncryptionKey).filter_by(user_id=current_user.id).delete()

    # Delete all refresh tokens
    db.query(RefreshToken).filter_by(user_id=current_user.id).delete()

    # Delete user record
    db.query(User).filter_by(id=current_user.id).delete()

    db.commit()

    return {"message": "Your account and all associated data have been deleted."}

@app.delete("/devices/{device_id}")
def delete_device(
    device_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Lookup the device owned by this user
    device = db.query(Device).filter_by(device_id=device_id, user_id=current_user.id).first()

    if not device:
        raise HTTPException(status_code=404, detail="Device not found")

    db.delete(device)
    db.commit()

    return {"message": f"Device '{device.device_name}' deleted successfully"}

@app.delete("/clipboard")
def delete_clipboard_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    deleted_count = db.query(Clipboard).filter_by(user_id=current_user.id).delete()
    db.commit()
    return {"message": f"{deleted_count} clipboard entries deleted."}

@app.websocket("/ws/clipboard")
async def websocket_clipboard(websocket: WebSocket, token: str):
    # Validate user + device
    user = get_user_from_token_ws(token)
    if not user:
        await websocket.close(code=1008)
        return

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        exp = payload.get("exp")
        device_id = payload.get("device_id")

        if not exp or not device_id:
            await websocket.close(code=1008)
            return
    except JWTError:
        await websocket.close(code=1008)
        return

    await websocket.accept()
    manager.connect(user.id, device_id, websocket)
    db = SessionLocal()

    try:
        while True:
            # Expiry check
            if datetime.utcnow().timestamp() > exp:
                await websocket.send_json({"type": "error", "message": "Token expired"})
                await websocket.close(code=4001)
                break

            try:
                data = await asyncio.wait_for(websocket.receive_json(), timeout=45)
            except asyncio.TimeoutError:
                await websocket.send_json({"type": "ping"})
                try:
                    pong = await asyncio.wait_for(websocket.receive_json(), timeout=10)
                    if pong.get("type") != "pong":
                        raise ValueError("Invalid pong")
                    continue
                except Exception:
                    await websocket.close(code=4002)
                    break

            if data.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
                continue

            text = data.get("text")
            if not text:
                continue

            # Store encrypted clipboard
            key_entry = db.query(EncryptionKey).filter_by(user_id=user.id).first()
            if not key_entry:
                key_entry = EncryptionKey(user_id=user.id, key=get_random_bytes(32))
                db.add(key_entry)
                db.commit()
                db.refresh(key_entry)

            encrypted_data, nonce = encrypt_clipboard(text, key_entry.key)
            new_entry = Clipboard(
                user_id=user.id,
                encrypted_data=encrypted_data,
                nonce=nonce,
                timestamp=datetime.utcnow()
            )
            db.add(new_entry)
            db.commit()

            await manager.broadcast_to_user(
                user_id=user.id,
                message={
                    "text": text,
                    "timestamp": new_entry.timestamp.isoformat()
                },
                exclude_device=device_id
            )

    except WebSocketDisconnect:
        pass
    finally:
        manager.disconnect(user.id, device_id)
        db.close()


@app.get("/sessions", response_model=List[SessionInfo])
def get_active_sessions(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    sessions = db.query(RefreshToken).filter(RefreshToken.user_id == current_user.id).all()
    return [
        {
            "device_id": session.device_id,
            "expiry": session.expiry
        }
        for session in sessions
    ]

@app.delete("/sessions/{device_id}")
def revoke_session(device_id: str, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    deleted = db.query(RefreshToken).filter_by(user_id=current_user.id, device_id=device_id).delete()
    db.commit()
    if deleted:
        return {"message": "Session revoked"}
    raise HTTPException(status_code=404, detail="Session not found")