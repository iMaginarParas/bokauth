from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from supabase import create_client, Client
import os
from typing import Optional
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Initialize FastAPI app
app = FastAPI(title="Supabase Auth API", version="1.0.0")

# Environment configuration
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
PORT = int(os.getenv("PORT", 8000))

# CORS configuration based on environment
if ENVIRONMENT == "production":
    allowed_origins = [FRONTEND_URL]
else:
    allowed_origins = ["*"]  # Allow all origins in development

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Supabase configuration - ONLY from environment variables
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")

# Validate required environment variables
if not SUPABASE_URL:
    raise ValueError("SUPABASE_URL environment variable is required")
if not SUPABASE_ANON_KEY:
    raise ValueError("SUPABASE_ANON_KEY environment variable is required")

# Create Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# Security
security = HTTPBearer()

# Pydantic models
class SignUpRequest(BaseModel):
    email: EmailStr
    password: str

class SignInRequest(BaseModel):
    email: EmailStr
    password: str

class VerifyOTPRequest(BaseModel):
    email: EmailStr
    token: str

class ResendOTPRequest(BaseModel):
    email: EmailStr

class GoogleAuthRequest(BaseModel):
    access_token: str

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class AuthResponse(BaseModel):
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    user_id: Optional[str] = None
    email: Optional[str] = None
    message: str
    requires_verification: bool = False

# Helper functions
def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Extract and validate user from JWT token"""
    token = credentials.credentials
    try:
        # Verify the JWT token with Supabase
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
            detail="Invalid token"
        )

# Auth routes
@app.post("/auth/signup", response_model=AuthResponse)
async def sign_up(request: SignUpRequest):
    """Sign up with email and password (sends OTP for verification)"""
    try:
        response = supabase.auth.sign_up({
            "email": request.email,
            "password": request.password,
        })
        
        if response.user:
            # Check if email confirmation is required
            if not response.user.email_confirmed_at:
                return AuthResponse(
                    message="Registration successful. Please check your email for verification code.",
                    requires_verification=True,
                    user_id=response.user.id,
                    email=response.user.email
                )
            else:
                return AuthResponse(
                    access_token=response.session.access_token if response.session else None,
                    refresh_token=response.session.refresh_token if response.session else None,
                    user_id=response.user.id,
                    email=response.user.email,
                    message="Registration and login successful",
                    requires_verification=False
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Registration failed"
            )
    except Exception as e:
        error_msg = str(e)
        if "User already registered" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="User already exists with this email"
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Registration failed: {error_msg}"
        )

@app.post("/auth/verify-otp", response_model=AuthResponse)
async def verify_otp(request: VerifyOTPRequest):
    """Verify email with OTP code"""
    try:
        response = supabase.auth.verify_otp({
            "email": request.email,
            "token": request.token,
            "type": "signup"
        })
        
        if response.user and response.session:
            return AuthResponse(
                access_token=response.session.access_token,
                refresh_token=response.session.refresh_token,
                user_id=response.user.id,
                email=response.user.email,
                message="Email verified successfully",
                requires_verification=False
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired verification code"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Verification failed: {str(e)}"
        )

@app.post("/auth/resend-otp")
async def resend_otp(request: ResendOTPRequest):
    """Resend OTP verification email"""
    try:
        response = supabase.auth.resend({
            "type": "signup",
            "email": request.email
        })
        
        return {"message": "Verification email sent successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to resend verification email: {str(e)}"
        )

@app.post("/auth/signin", response_model=AuthResponse)
async def sign_in(request: SignInRequest):
    """Sign in with email and password"""
    try:
        response = supabase.auth.sign_in_with_password({
            "email": request.email,
            "password": request.password
        })
        
        if response.user and response.session:
            return AuthResponse(
                access_token=response.session.access_token,
                refresh_token=response.session.refresh_token,
                user_id=response.user.id,
                email=response.user.email,
                message="Login successful",
                requires_verification=False
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid credentials"
            )
    except Exception as e:
        error_msg = str(e)
        if "Invalid login credentials" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        elif "Email not confirmed" in error_msg:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Please verify your email before signing in"
            )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Login failed: {error_msg}"
        )

@app.post("/auth/google", response_model=AuthResponse)
async def google_auth(request: GoogleAuthRequest):
    """Sign in with Google OAuth"""
    try:
        # Note: This requires the Google access token from the frontend
        # The frontend should handle Google OAuth and send the access token
        response = supabase.auth.sign_in_with_oauth({
            "provider": "google",
            "options": {
                "access_token": request.access_token
            }
        })
        
        if response.user and response.session:
            return AuthResponse(
                access_token=response.session.access_token,
                refresh_token=response.session.refresh_token,
                user_id=response.user.id,
                email=response.user.email,
                message="Google login successful",
                requires_verification=False
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Google authentication failed"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Google authentication failed: {str(e)}"
        )

@app.get("/auth/google/url")
async def get_google_oauth_url():
    """Get Google OAuth URL for frontend"""
    try:
        response = supabase.auth.sign_in_with_oauth({
            "provider": "google",
            "options": {
                "redirect_to": f"{FRONTEND_URL}/auth/callback"
            }
        })
        
        return {"url": response.url}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to generate Google OAuth URL: {str(e)}"
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
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token refresh failed: {str(e)}"
        )

@app.post("/auth/signout")
async def sign_out(current_user = Depends(get_current_user)):
    """Sign out current user"""
    try:
        response = supabase.auth.sign_out()
        return {"message": "Signed out successfully"}
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Sign out failed: {str(e)}"
        )

@app.get("/auth/user")
async def get_user_profile(current_user = Depends(get_current_user)):
    """Get current user profile"""
    return {
        "user_id": current_user.id,
        "email": current_user.email,
        "email_confirmed": current_user.email_confirmed_at is not None,
        "created_at": current_user.created_at,
        "last_sign_in": current_user.last_sign_in_at
    }

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "message": "Supabase Auth API is running",
        "timestamp": datetime.now().isoformat(),
        "environment": ENVIRONMENT
    }

# Protected route example
@app.get("/protected")
async def protected_route(current_user = Depends(get_current_user)):
    """Example protected route"""
    return {
        "message": f"Hello {current_user.email}, this is a protected route!",
        "user_id": current_user.id
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=PORT)