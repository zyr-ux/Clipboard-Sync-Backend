from datetime import datetime
from sqlalchemy.orm import Session
from models import BlacklistedToken

def cleanup_expired_blacklisted_tokens(db: Session):
    db.query(BlacklistedToken).filter(BlacklistedToken.expiry < datetime.utcnow()).delete()
    db.commit()

def cleanup_expired_refresh_tokens(db: Session):
    db.query(RefreshToken).filter(RefreshToken.expiry < datetime.utcnow()).delete()
    db.commit()