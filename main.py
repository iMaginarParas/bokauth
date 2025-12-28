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
app = FastAPI(title="Supabase Multi-Auth API", version="1.0.0")

# Environment configuration
ENVIRONMENT = os.getenv("ENVIRONMENT", "development")
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://localhost:3000")
PORT = int(os.getenv("PORT", 8000))

# Test credentials configuration (only for development)
TEST_EMAIL = "test@sobookey.in"
TEST_OTP = "123456"
TEST_PHONE = "+11234567890"

# Test user session storage (in production, use a proper session store)
test_sessions = {}

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

def is_test_email(email: str) -> bool:
    """Check if email is a test email"""
    return ENVIRONMENT == "development" and email == TEST_EMAIL

def is_test_phone(phone: str) -> bool:
    """Check if phone is a test phone"""
    try:
        clean_phone = validate_phone_number(phone)
        return ENVIRONMENT == "development" and clean_phone == TEST_PHONE
    except:
        return False

def generate_test_token(identifier: str) -> str:
    """Generate a simple test token for development"""
    import uuid
    token = f"test_token_{uuid.uuid4().hex[:16]}"
    test_sessions[token] = {
        "identifier": identifier,
        "created_at": datetime.now().isoformat(),
        "user_id": f"test_user_{identifier.replace('@', '_').replace('+', '_')}"
    }
    return token

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """Extract and validate user from JWT token"""
    token = credentials.credentials
    
    # Check if it's a test token first
    if ENVIRONMENT == "development" and token in test_sessions:
        session_data = test_sessions[token]
        # Create a mock user object
        class MockUser:
            def __init__(self, session_data):
                self.id = session_data["user_id"]
                self.email = session_data["identifier"] if "@" in session_data["identifier"] else None
                self.phone = session_data["identifier"] if "+" in session_data["identifier"] else None
                self.email_confirmed_at = datetime.now().isoformat() if self.email else None
                self.phone_confirmed_at = datetime.now().isoformat() if self.phone else None
                self.created_at = session_data["created_at"]
                self.last_sign_in_at = datetime.now().isoformat()
        
        return MockUser(session_data)
    
    # Otherwise, use Supabase validation
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
    token: Optional[str] = None  # OTP token - optional when using password
    password: Optional[str] = None  # Password - optional when using OTP

class ResendOTPRequest(BaseModel):
    email: Optional[EmailStr] = None
    phone: Optional[str] = None

class RefreshTokenRequest(BaseModel):
    refresh_token: str

class EmailPasswordRegisterRequest(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = None

class EmailPasswordLoginRequest(BaseModel):
    email: EmailStr
    password: str

class ResendConfirmationRequest(BaseModel):
    email: EmailStr

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
        response_data = {
            "message": "Supabase Multi-Auth API is running",
            "timestamp": datetime.now().isoformat(),
            "environment": ENVIRONMENT,
            "auth_methods": ["email_otp", "sms_otp", "email_password", "email_confirmation"],
            "status": "healthy"
        }
        
        # Add test credentials info in development
        if ENVIRONMENT == "development":
            response_data["test_mode"] = True
            response_data["test_credentials"] = {
                "email": TEST_EMAIL,
                "phone": TEST_PHONE,
                "otp": TEST_OTP,
                "note": "Use these credentials for testing without sending real OTPs"
            }
        
        return response_data
    except Exception as e:
        return {
            "message": "API is running but there might be configuration issues",
            "error": str(e),
            "status": "degraded"
        }

@app.post("/auth/signin/email", response_model=AuthResponse)
async def sign_in_with_email(request: EmailSignInRequest):
    """Send OTP to email for passwordless sign-in"""
    try:
        # Handle test email in development mode
        if is_test_email(request.email):
            return AuthResponse(
                access_token=None,
                refresh_token=None,
                user_id=None,
                email=request.email,
                phone=None,
                message=f"[TEST MODE] OTP sent to {request.email}. Use OTP: {TEST_OTP}",
                requires_verification=True
            )
        
        # Use Supabase's signInWithOtp for real emails
        response = supabase.auth.sign_in_with_otp({
            "email": request.email
        })
        
        return AuthResponse(
            access_token=None,
            refresh_token=None,
            user_id=None,
            email=request.email,
            phone=None,
            message="OTP sent to your email. Please check your inbox.",
            requires_verification=True
        )
    except Exception as e:
        error_msg = str(e)
        print(f"Email sign-in error: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to send OTP: {error_msg}"
        )

@app.post("/auth/signin/phone", response_model=AuthResponse)
async def sign_in_with_phone(request: PhoneSignInRequest):
    """Send OTP to phone for passwordless sign-in"""
    try:
        # Validate and format phone number
        clean_phone = validate_phone_number(request.phone)
        
        # Handle test phone in development mode
        if is_test_phone(clean_phone):
            return AuthResponse(
                access_token=None,
                refresh_token=None,
                user_id=None,
                email=None,
                phone=clean_phone,
                message=f"[TEST MODE] OTP sent to {clean_phone}. Use OTP: {TEST_OTP}",
                requires_verification=True
            )
        
        # Use Supabase's signInWithOtp for real phone numbers
        response = supabase.auth.sign_in_with_otp({
            "phone": clean_phone
        })
        
        return AuthResponse(
            access_token=None,
            refresh_token=None,
            user_id=None,
            email=None,
            phone=clean_phone,
            message="OTP sent to your phone. Please check your messages.",
            requires_verification=True
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        error_msg = str(e)
        print(f"Phone sign-in error: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to send OTP: {error_msg}"
        )

@app.post("/auth/verify", response_model=AuthResponse)
async def verify_otp(request: VerifyOTPRequest):
    """Verify OTP for email or phone"""
    try:
        # Validate that either email or phone is provided
        if not request.email and not request.phone:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either email or phone must be provided"
            )
        
        # Validate that either token (OTP) or password is provided
        if not request.token and not request.password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either OTP token or password must be provided"
            )
        
        # Handle test credentials in development mode
        if ENVIRONMENT == "development":
            # Test email verification
            if request.email and is_test_email(request.email):
                if request.token == TEST_OTP or request.password:  # Accept test OTP or any password
                    test_token = generate_test_token(request.email)
                    return AuthResponse(
                        access_token=test_token,
                        refresh_token=f"refresh_{test_token}",
                        user_id=f"test_user_{request.email.replace('@', '_').replace('.', '_')}",
                        email=request.email,
                        phone=None,
                        message="[TEST MODE] Verification successful!",
                        requires_verification=False
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"[TEST MODE] Invalid OTP. Use: {TEST_OTP}"
                    )
            
            # Test phone verification
            if request.phone:
                clean_phone = validate_phone_number(request.phone)
                if is_test_phone(clean_phone):
                    if request.token == TEST_OTP:
                        test_token = generate_test_token(clean_phone)
                        return AuthResponse(
                            access_token=test_token,
                            refresh_token=f"refresh_{test_token}",
                            user_id=f"test_user_{clean_phone.replace('+', '_')}",
                            email=None,
                            phone=clean_phone,
                            message="[TEST MODE] Verification successful!",
                            requires_verification=False
                        )
                    else:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"[TEST MODE] Invalid OTP. Use: {TEST_OTP}"
                        )
        
        # Real OTP verification using Supabase
        if request.token:  # OTP verification
            verification_data = {
                "token": request.token,
                "type": "sms" if request.phone else "email"
            }
            
            if request.email:
                verification_data["email"] = request.email
            elif request.phone:
                clean_phone = validate_phone_number(request.phone)
                verification_data["phone"] = clean_phone
            
            response = supabase.auth.verify_otp(verification_data)
        else:  # Password verification
            if request.email:
                response = supabase.auth.sign_in_with_password({
                    "email": request.email,
                    "password": request.password
                })
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Password authentication only supported for email"
                )
        
        # Check if we got a valid session
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
                detail="Verification failed"
            )
            
    except HTTPException:
        raise
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        error_msg = str(e)
        print(f"Verification error: {error_msg}")
        
        # Handle specific Supabase errors
        if "invalid" in error_msg.lower() or "expired" in error_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid or expired OTP"
            )
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Verification failed: {error_msg}"
        )

@app.post("/auth/resend")
async def resend_otp(request: ResendOTPRequest):
    """Resend OTP to email or phone"""
    try:
        if not request.email and not request.phone:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either email or phone must be provided"
            )
        
        # Handle test credentials
        if request.email and is_test_email(request.email):
            return {"message": f"[TEST MODE] OTP resent to {request.email}. Use OTP: {TEST_OTP}"}
        
        if request.phone:
            clean_phone = validate_phone_number(request.phone)
            if is_test_phone(clean_phone):
                return {"message": f"[TEST MODE] OTP resent to {clean_phone}. Use OTP: {TEST_OTP}"}
        
        # Resend using Supabase
        resend_data = {
            "type": "sms" if request.phone else "signup"
        }
        
        if request.email:
            resend_data["email"] = request.email
        elif request.phone:
            clean_phone = validate_phone_number(request.phone)
            resend_data["phone"] = clean_phone
        
        response = supabase.auth.resend(resend_data)
        
        return {"message": "OTP resent successfully"}
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except Exception as e:
        error_msg = str(e)
        print(f"Resend OTP error: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to resend OTP: {error_msg}"
        )

@app.post("/auth/refresh", response_model=AuthResponse)
async def refresh_token(request: RefreshTokenRequest):
    """Refresh access token using refresh token"""
    try:
        # Handle test tokens
        if ENVIRONMENT == "development" and request.refresh_token.startswith("refresh_test_token_"):
            original_token = request.refresh_token.replace("refresh_", "")
            if original_token in test_sessions:
                # Generate new test token
                session_data = test_sessions[original_token]
                new_token = generate_test_token(session_data["identifier"])
                
                return AuthResponse(
                    access_token=new_token,
                    refresh_token=f"refresh_{new_token}",
                    user_id=session_data["user_id"],
                    email=session_data["identifier"] if "@" in session_data["identifier"] else None,
                    phone=session_data["identifier"] if "+" in session_data["identifier"] else None,
                    message="[TEST MODE] Token refreshed successfully",
                    requires_verification=False
                )
        
        # Use Supabase's refresh token
        response = supabase.auth.refresh_session(request.refresh_token)
        
        if response.session and response.user:
            return AuthResponse(
                access_token=response.session.access_token,
                refresh_token=response.session.refresh_token,
                user_id=response.user.id,
                email=response.user.email,
                phone=response.user.phone,
                message="Token refreshed successfully",
                requires_verification=False
            )
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
        # For test users, just remove from test_sessions
        if ENVIRONMENT == "development" and hasattr(current_user, 'id') and current_user.id.startswith('test_user_'):
            # Find and remove test tokens
            tokens_to_remove = []
            for token, session_data in test_sessions.items():
                if session_data["user_id"] == current_user.id:
                    tokens_to_remove.append(token)
            
            for token in tokens_to_remove:
                del test_sessions[token]
            
            return {"message": "[TEST MODE] Signed out successfully"}
        
        # Regular Supabase flow
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
    user_metadata = getattr(current_user, 'user_metadata', {}) or {}
    
    return {
        "user_id": current_user.id,
        "email": current_user.email,
        "phone": current_user.phone,
        "name": user_metadata.get('name'),
        "email_confirmed": current_user.email_confirmed_at is not None,
        "phone_confirmed": current_user.phone_confirmed_at is not None,
        "created_at": current_user.created_at,
        "last_sign_in": current_user.last_sign_in_at,
        "is_test_user": ENVIRONMENT == "development" and current_user.id.startswith('test_user_')
    }

@app.post("/auth/register", response_model=AuthResponse)
async def register_with_password(request: EmailPasswordRegisterRequest):
    """Register new user with email and password"""
    try:
        # Handle test email in development
        if ENVIRONMENT == "development" and request.email == TEST_EMAIL:
            # For test mode, create a simple mock registration
            test_token = generate_test_token(request.email)
            message = "[TEST MODE] Registration successful!"
            if request.name:
                message += f" Name: {request.name}"
            
            return AuthResponse(
                access_token=test_token,
                refresh_token=f"refresh_{test_token}",
                user_id=f"test_user_{request.email.replace('@', '_').replace('.', '_')}",
                email=request.email,
                phone=None,
                message=message,
                requires_verification=False
            )
        
        # Regular Supabase registration
        signup_data = {
            "email": request.email,
            "password": request.password
        }
        
        # Only add name to metadata if provided
        if request.name:
            signup_data["options"] = {
                "data": {
                    "name": request.name
                }
            }
        
        response = supabase.auth.sign_up(signup_data)
        
        if response.user and response.session:
            return AuthResponse(
                access_token=response.session.access_token,
                refresh_token=response.session.refresh_token,
                user_id=response.user.id,
                email=response.user.email,
                phone=None,
                message="Registration successful!",
                requires_verification=not response.user.email_confirmed_at
            )
        elif response.user:
            # User created but needs email confirmation
            return AuthResponse(
                access_token=None,
                refresh_token=None,
                user_id=response.user.id,
                email=response.user.email,
                phone=None,
                message="Registration successful! Please check your email for confirmation.",
                requires_verification=True
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Registration failed"
            )
    except Exception as e:
        error_msg = str(e)
        print(f"Registration error: {error_msg}")
        
        # Handle common Supabase errors
        if "already registered" in error_msg.lower() or "already exists" in error_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email already registered"
            )
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Registration failed: {error_msg}"
        )

@app.post("/auth/login", response_model=AuthResponse)
async def login_with_password(request: EmailPasswordLoginRequest):
    """Login user with email and password"""
    try:
        # Handle test email in development
        if ENVIRONMENT == "development" and request.email == TEST_EMAIL:
            # For test mode, accept any password
            test_token = generate_test_token(request.email)
            return AuthResponse(
                access_token=test_token,
                refresh_token=f"refresh_{test_token}",
                user_id=f"test_user_{request.email.replace('@', '_').replace('.', '_')}",
                email=request.email,
                phone=None,
                message="[TEST MODE] Login successful!",
                requires_verification=False
            )
        
        # Regular Supabase login
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
                phone=response.user.phone,
                message="Login successful!",
                requires_verification=False
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
    except Exception as e:
        error_msg = str(e)
        print(f"Login error: {error_msg}")
        
        # Handle common authentication errors
        if "invalid" in error_msg.lower() or "credentials" in error_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        elif "email not confirmed" in error_msg.lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Please verify your email address before logging in. Check your inbox for confirmation email."
            )
        
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Login failed: {error_msg}"
        )

@app.post("/auth/resend-confirmation")
async def resend_email_confirmation(request: ResendConfirmationRequest):
    """Resend email confirmation link"""
    try:
        # Handle test email
        if ENVIRONMENT == "development" and request.email == TEST_EMAIL:
            return {"message": "[TEST MODE] Email confirmation not required for test email"}
        
        # Resend confirmation email
        response = supabase.auth.resend({
            "type": "signup",
            "email": request.email
        })
        
        return {"message": "Confirmation email sent successfully. Please check your inbox."}
        
    except Exception as e:
        error_msg = str(e)
        print(f"Resend confirmation error: {error_msg}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Failed to resend confirmation: {error_msg}"
        )

@app.get("/protected")
async def protected_route(current_user = Depends(get_current_user)):
    """Example protected route"""
    identifier = current_user.email or current_user.phone
    is_test = ENVIRONMENT == "development" and current_user.id.startswith('test_user_')
    test_prefix = "[TEST MODE] " if is_test else ""
    
    return {
        "message": f"{test_prefix}Hello {identifier}, this is a protected route!",
        "user_id": current_user.id,
        "is_test_user": is_test
    }

if __name__ == "__main__":
    import uvicorn
    print(f"Starting server on port {PORT}")
    print(f"Environment: {ENVIRONMENT}")
    print("Available authentication methods: Email OTP, SMS OTP, Email/Password")
    if ENVIRONMENT == "development":
        print(f"Test credentials available:")
        print(f"  Email: {TEST_EMAIL}")
        print(f"  Phone: {TEST_PHONE}")
        print(f"  OTP: {TEST_OTP}")
        print(f"  Password: Any password works for test email")
    uvicorn.run(app, host="0.0.0.0", port=PORT)