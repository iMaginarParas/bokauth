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
                "password": "Any password works for test email in development mode"
            }
        
        return response_data
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
        # Handle test email
        if is_test_email(request.email):
            print(f"Test email signin: {request.email}")
            return AuthResponse(
                message=f"[TEST MODE] Email verification code sent. Use OTP: {TEST_OTP}",
                requires_verification=True,
                email=request.email
            )
        
        # Regular Supabase flow
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
        
        # Handle test phone
        if is_test_phone(clean_phone):
            print(f"Test phone signin: {clean_phone}")
            return AuthResponse(
                message=f"[TEST MODE] SMS verification code sent. Use OTP: {TEST_OTP}",
                requires_verification=True,
                phone=clean_phone
            )
        
        # Regular Supabase flow
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
    """Verify OTP code (email or SMS) OR authenticate with email/password"""
    try:
        # Validate input - must provide either token OR password, not both or neither
        if not request.token and not request.password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Either 'token' (for OTP) or 'password' (for email/password auth) is required"
            )
        
        if request.token and request.password:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Provide either 'token' OR 'password', not both"
            )
        
        # PASSWORD AUTHENTICATION PATH
        if request.password and request.email:
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
                    message="[TEST MODE] Password login successful!",
                    requires_verification=False
                )
            
            # Regular Supabase password authentication
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
                    message="Password login successful!",
                    requires_verification=False
                )
            else:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Invalid email or password"
                )
        
        elif request.password and not request.email:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Email is required when using password authentication"
            )
        
        # OTP VERIFICATION PATH (existing logic)
        elif request.token:
            # Handle test credentials
            if request.email and is_test_email(request.email):
                if request.token == TEST_OTP:
                    test_token = generate_test_token(request.email)
                    print(f"Test email OTP verified for: {request.email}")
                    return AuthResponse(
                        access_token=test_token,
                        refresh_token=f"refresh_{test_token}",
                        user_id=f"test_user_{request.email.replace('@', '_')}",
                        email=request.email,
                        phone=None,
                        message="[TEST MODE] OTP verification successful!",
                        requires_verification=False
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid OTP. For test email, use: {TEST_OTP}"
                    )
            
            if request.phone and is_test_phone(request.phone):
                if request.token == TEST_OTP:
                    clean_phone = validate_phone_number(request.phone)
                    test_token = generate_test_token(clean_phone)
                    print(f"Test phone OTP verified for: {clean_phone}")
                    return AuthResponse(
                        access_token=test_token,
                        refresh_token=f"refresh_{test_token}",
                        user_id=f"test_user_{clean_phone.replace('+', '_')}",
                        email=None,
                        phone=clean_phone,
                        message="[TEST MODE] OTP verification successful!",
                        requires_verification=False
                    )
                else:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=f"Invalid OTP. For test phone, use: {TEST_OTP}"
                    )
            
            # Regular Supabase OTP verification
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
                    detail="Either email or phone number is required for OTP verification"
                )
            
            if response.user and response.session:
                return AuthResponse(
                    access_token=response.session.access_token,
                    refresh_token=response.session.refresh_token,
                    user_id=response.user.id,
                    email=response.user.email,
                    phone=response.user.phone,
                    message="OTP verification successful!",
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
    except HTTPException:
        # Re-raise HTTPExceptions as-is
        raise
    except Exception as e:
        error_msg = str(e)
        print(f"Verification error: {error_msg}")
        
        # Handle common authentication errors for password login
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
            detail=f"Authentication failed: {error_msg}"
        )

@app.post("/auth/resend-otp")
async def resend_otp(request: ResendOTPRequest):
    """Resend OTP verification (email or SMS)"""
    try:
        if request.email:
            # Handle test email
            if is_test_email(request.email):
                return {"message": f"[TEST MODE] Email verification code sent. Use OTP: {TEST_OTP}"}
            
            response = supabase.auth.sign_in_with_otp({
                "email": request.email
            })
            return {"message": "Email verification code sent successfully"}
        elif request.phone:
            clean_phone = validate_phone_number(request.phone)
            
            # Handle test phone
            if is_test_phone(clean_phone):
                return {"message": f"[TEST MODE] SMS verification code sent. Use OTP: {TEST_OTP}"}
            
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
        # Handle test tokens
        if ENVIRONMENT == "development" and request.refresh_token.startswith("refresh_test_token_"):
            original_token = request.refresh_token.replace("refresh_", "")
            if original_token in test_sessions:
                session_data = test_sessions[original_token]
                new_token = generate_test_token(session_data["identifier"])
                return {
                    "access_token": new_token,
                    "refresh_token": f"refresh_{new_token}",
                    "message": "[TEST MODE] Token refreshed successfully"
                }
        
        # Regular Supabase flow
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
    return {
        "user_id": current_user.id,
        "email": current_user.email,
        "phone": current_user.phone,
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
            return AuthResponse(
                access_token=test_token,
                refresh_token=f"refresh_{test_token}",
                user_id=f"test_user_{request.email.replace('@', '_').replace('.', '_')}",
                email=request.email,
                phone=None,
                message="[TEST MODE] Registration successful!",
                requires_verification=False
            )
        
        # Regular Supabase registration
        response = supabase.auth.sign_up({
            "email": request.email,
            "password": request.password
        })
        
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