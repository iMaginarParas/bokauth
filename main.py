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
    allowed_origins = [FRONTEND_URL] if FRONTEND_URL else ["*"]
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
try:
    supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)
except Exception as e:
    print(f"Failed to create Supabase client: {e}")
    raise ValueError(f"Could not initialize Supabase client: {e}")

# Security
security = HTTPBearer()

# Pydantic models
class EmailOTPRequest(BaseModel):
    email: EmailStr

class VerifyOTPRequest(BaseModel):
    email: EmailStr
    token: str

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

# Helper functions
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
            detail="Invalid token"
        )

# Auth routes
@app.post("/auth/send-otp")
async def send_otp(request: EmailOTPRequest):
    """Send 6-digit OTP code to email for authentication"""
    try:
        # For email OTP, we need to use sign_up first to create user
        # This sends a proper OTP code for email verification
        response = supabase.auth.sign_up({
            "email": request.email,
            "password": "temp_password_123!"  # Required but not used for OTP flow
        })
        
        print(f"Signup OTP response: {response}")  # Debug log
        return {
            "message": "6-digit OTP code sent to your email for verification!",
            "email": request.email,
            "debug": "Used signup method for OTP"
        }
                
    except Exception as e:
        error_msg = str(e)
        print(f"Send OTP error: {error_msg}")  # Debug log
        
        # If user already exists, that's actually fine for our use case
        if "already registered" in error_msg or "User already registered" in error_msg:
            # User exists, send them a password reset OTP instead
            try:
                response = supabase.auth.reset_password_email(request.email)
                return {
                    "message": "6-digit OTP code sent to your email for verification!",
                    "email": request.email,
                    "debug": "Used password reset for existing user OTP"
                }
            except Exception as reset_error:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Failed to send OTP: {str(reset_error)}"
                )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Failed to send OTP: {error_msg}"
            )

@app.post("/auth/verify-otp", response_model=AuthResponse)
async def verify_otp(request: VerifyOTPRequest):
    """Verify the 6-digit OTP code and authenticate user"""
    try:
        # First try verifying as signup OTP (for new users)
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
                    message="OTP verification successful! Welcome!"
                )
        except Exception as signup_verify_error:
            print(f"Signup verification failed: {signup_verify_error}")
            
            # If signup OTP fails, try as recovery OTP (for existing users)
            try:
                response = supabase.auth.verify_otp({
                    "email": request.email,
                    "token": request.token,
                    "type": "recovery"
                })
                
                if response.user and response.session:
                    return AuthResponse(
                        access_token=response.session.access_token,
                        refresh_token=response.session.refresh_token,
                        user_id=response.user.id,
                        email=response.user.email,
                        message="OTP verification successful! Welcome back!"
                    )
            except Exception as recovery_verify_error:
                print(f"Recovery verification failed: {recovery_verify_error}")
        
        # If both methods fail
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired OTP code. Please try again."
        )
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"OTP verification error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"OTP verification failed: {str(e)}"
        )

@app.post("/auth/resend-otp")
async def resend_otp(request: EmailOTPRequest):
    """Resend OTP code to email"""
    try:
        # Try sending as password reset (works for existing users)
        response = supabase.auth.reset_password_email(request.email)
        return {
            "message": "New OTP code sent to your email!",
            "email": request.email
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to resend OTP: {str(e)}"
        )

@app.get("/auth/google/url")
async def get_google_oauth_url():
    """Get Google OAuth URL for frontend redirection"""
    try:
        response = supabase.auth.sign_in_with_oauth({
            "provider": "google",
            "options": {
                "redirect_to": f"{FRONTEND_URL}/auth/callback"
            }
        })
        
        return {
            "url": response.url,
            "message": "Redirect user to this URL for Google OAuth"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to generate Google OAuth URL: {str(e)}"
        )

@app.post("/auth/google/callback", response_model=AuthResponse)
async def google_callback(access_token: str, refresh_token: str):
    """Handle Google OAuth callback - frontend sends tokens after OAuth"""
    try:
        # Set the session with tokens received from frontend
        response = supabase.auth.set_session(access_token, refresh_token)
        
        if response.user and response.session:
            return AuthResponse(
                access_token=response.session.access_token,
                refresh_token=response.session.refresh_token,
                user_id=response.user.id,
                email=response.user.email,
                message="Google authentication successful!"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid Google OAuth tokens"
            )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Google authentication failed: {str(e)}"
        )

@app.post("/auth/refresh")
async def refresh_token(request: RefreshTokenRequest):
    """Refresh access token using refresh token"""
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
        "created_at": current_user.created_at,
        "last_sign_in": current_user.last_sign_in_at
    }

@app.get("/")
async def root():
    """Health check endpoint"""
    return {
        "message": "Supabase OTP + Google Auth API is running!",
        "timestamp": datetime.now().isoformat(),
        "environment": ENVIRONMENT,
        "auth_methods": ["email_otp", "google_oauth"]
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