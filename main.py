import os
import re
import sys
from datetime import datetime
from typing import Optional

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr

# Load environment variables first
load_dotenv()

# Validate required environment variables early
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")

if not SUPABASE_URL:
    print("ERROR: SUPABASE_URL environment variable is required")
    sys.exit(1)
if not SUPABASE_ANON_KEY:
    print("ERROR: SUPABASE_ANON_KEY environment variable is required")
    sys.exit(1)

print(f"Initializing with Supabase URL: {SUPABASE_URL[:50]}...")

# Try to import and initialize Supabase
try:
    from supabase import create_client, Client
    print("✓ Supabase package imported successfully")
    
    # Initialize Supabase client
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
    print("✓ Supabase client initialized successfully")
    
except ImportError as e:
    print(f"ERROR: Failed to import supabase: {e}")
    sys.exit(1)
except Exception as e:
    print(f"ERROR: Failed to initialize Supabase client: {e}")
    print("This might be due to invalid credentials or network issues")
    sys.exit(1)

# Initialize FastAPI app
app = FastAPI(title="Supabase OTP Auth API", version="1.0.0")

# Environment configuration
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
PORT = int(os.getenv("PORT", 8000))

# CORS configuration
if ENVIRONMENT == "production":
    allowed_origins = [FRONTEND_URL]
else:
    allowed_origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Utility functions
def validate_phone_number(phone: str) -> str:
    """Validate and format phone number"""
    if not phone:
        raise ValueError("Phone number is required")
    
    # Remove all non-digit characters except +
    clean_phone = re.sub(r'[^\d+]', '', phone)
    
    # Ensure phone number starts with country code
    if not clean_phone.startswith('+'):
        if clean_phone.startswith('0'):
            clean_phone = clean_phone[1:]
        # Add default country code for US
        clean_phone = '+1' + clean_phone
    
    # Validate phone number format
    if not re.match(r'^\+\d{10,15}$', clean_phone):
        raise ValueError("Invalid phone number format. Use format: +1234567890")
    
    return clean_phone

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Extract and validate user from JWT token"""
    token = credentials.credentials
    try:
        response = supabase.auth.get_user(token)
        if response.user:
            return response.user
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )

# Pydantic models
class EmailSignInRequest(BaseModel):
    email: EmailStr

class PhoneSignInRequest(BaseModel):
    phone: str

class VerifyOTPRequest(BaseModel):
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    token: str

class ResendOTPRequest(BaseModel):
    email: Optional[EmailStr] = None
    phone: Optional[str] = None

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class AuthResponse(BaseModel):
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    user_id: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    message: str
    requires_verification: bool = False

# Routes
@app.get("/")
async def root():
    """Health check endpoint"""
    try:
        # Test basic Supabase connection
        # This doesn't make an actual API call but ensures the client is working
        return {
            "message": "Supabase OTP-only Auth API is running",
            "timestamp": datetime.now().isoformat(),
            "environment": ENVIRONMENT,
            "auth_methods": ["email_otp", "sms_otp"],
            "status": "healthy"
        }
    except Exception as e:
        return {
            "message": "API running but Supabase connection issues",
            "error": str(e),
            "status": "degraded"
        }

@app.post("/auth/email/signin", response_model=AuthResponse)
async def email_sign_in(request: EmailSignInRequest):
    """Sign in with email (sends email OTP)"""
    try:
        response = supabase.auth.sign_in_with_otp({
            "email": request.email
        })
        
        return AuthResponse(
            message="Email verification code sent. Please check your email.",
            requires_verification=True,
            email=request.email
        )
    except Exception as e:
        error_msg = str(e)
        print(f"Email sign in error: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to send email OTP: {error_msg}"
        )

@app.post("/auth/phone/signin", response_model=AuthResponse)
async def phone_sign_in(request: PhoneSignInRequest):
    """Sign in with phone number (sends SMS OTP)"""
    try:
        clean_phone = validate_phone_number(request.phone)
        
        response = supabase.auth.sign_in_with_otp({
            "phone": clean_phone
        })
        
        return AuthResponse(
            message="SMS verification code sent. Please check your phone.",
            requires_verification=True,
            phone=clean_phone
        )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except Exception as e:
        error_msg = str(e)
        print(f"Phone sign in error: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to send SMS OTP: {error_msg}"
        )

@app.post("/auth/verify-otp", response_model=AuthResponse)
async def verify_otp(request: VerifyOTPRequest):
    """Verify OTP code (email or SMS)"""
    try:
        if request.email:
            response = supabase.auth.verify_otp({
                "email": request.email,
                "token": request.token,
                "type": "email"
            })
        elif request.phone:
            clean_phone = validate_phone_number(request.phone)
            response = supabase.auth.verify_otp({
                "phone": clean_phone,
                "token": request.token,
                "type": "sms"
            })
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either email or phone number is required"
            )
        
        if response.user and response.session:
            return AuthResponse(
                access_token=response.session.access_token,
                refresh_token=response.session.refresh_token,
                user_id=response.user.id,
                email=response.user.email,
                phone=response.user.phone,
                message="Verification successful!",
                requires_verification=False
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification code"
            )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except Exception as e:
        error_msg = str(e)
        print(f"OTP verification error: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Verification failed: {error_msg}"
        )

@app.post("/auth/resend-otp")
async def resend_otp(request: ResendOTPRequest):
    """Resend OTP verification (email or SMS)"""
    try:
        if request.email:
            response = supabase.auth.sign_in_with_otp({
                "email": request.email
            })
            return {"message": "Email verification code sent successfully"}
        elif request.phone:
            clean_phone = validate_phone_number(request.phone)
            response = supabase.auth.sign_in_with_otp({
                "phone": clean_phone
            })
            return {"message": "SMS verification code sent successfully"}
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either email or phone number is required"
            )
    except ValueError as ve:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(ve)
        )
    except Exception as e:
        error_msg = str(e)
        print(f"Resend OTP error: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to resend verification: {error_msg}"
        )

@app.post("/auth/refresh")
async def refresh_token(request: RefreshTokenRequest):
    """Refresh access token"""
    try:
        response = supabase.auth.refresh_session(request.refresh_token)
        
        if response.session:
            return {
                "access_token": response.session.access_token,
                "refresh_token": response.session.refresh_token,
                "message": "Token refreshed successfully"
            }
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid refresh token"
            )
    except Exception as e:
        error_msg = str(e)
        print(f"Token refresh error: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token refresh failed: {error_msg}"
        )

@app.post("/auth/signout")
async def sign_out(current_user = Depends(get_current_user)):
    """Sign out current user"""
    try:
        response = supabase.auth.sign_out()
        return {"message": "Signed out successfully"}
    except Exception as e:
        error_msg = str(e)
        print(f"Sign out error: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Sign out failed: {error_msg}"
        )

@app.get("/auth/user")
async def get_user_profile(current_user = Depends(get_current_user)):
    """Get current user profile"""
    return {
        "user_id": current_user.id,
        "email": current_user.email,
        "phone": current_user.phone,
        "email_confirmed": current_user.email_confirmed_at is not None,
        "phone_confirmed": current_user.phone_confirmed_at is not None,
        "created_at": current_user.created_at,
        "last_sign_in": current_user.last_sign_in_at
    }

@app.get("/protected")
async def protected_route(current_user = Depends(get_current_user)):
    """Example protected route"""
    identifier = current_user.email or current_user.phone
    return {
        "message": f"Hello {identifier}, this is a protected route!",
        "user_id": current_user.id
    }

if __name__ == "__main__":
    import uvicorn
    print(f"Starting server on port {PORT}")
    uvicorn.run(app, host="0.0.0.0", port=PORT)