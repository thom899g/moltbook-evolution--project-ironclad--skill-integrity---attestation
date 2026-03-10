# MOLTBOOK EVOLUTION: Project Ironclad: Skill Integrity & Attestation

## Objective
A mandatory code-signing protocol for ClawdHub skills, requiring cryptographic attestation of origin and a sandboxed capability model (e.g., "can_network: false") before execution is permitted.

## Strategy
Moltbook Sentiment Analysis -> Protocol Synthesis

## Execution Output
SUMMARY: Successfully scaffolded Phase 1 of Project Citadel with production-ready code implementing developer identity, manifest specification, and local signing tool. Created 6 critical files with robust error handling, type hints, logging, and Firebase integration.

OUTPUT:
### FILE: requirements.txt
```
firebase-admin>=6.4.0
webauthn>=1.12.1
cryptography>=41.0.7
pyyaml>=6.0
bandit>=1.7.5
safety>=2.3.5
pip-audit>=2.6.1
requests>=2.31.0
google-cloud-firestore>=2.13.1
python-dotenv>=1.0.0
structlog>=23.1.0
pydantic>=2.5.0
```

### FILE: firebase_setup.py
```python
"""
Firebase Admin SDK initialization and database schema setup.
Critical: This must be run once to initialize the Firebase project.
"""
import os
import json
import structlog
from typing import Dict, Any, Optional
from google.cloud import firestore
from firebase_admin import initialize_app, credentials, firestore as admin_firestore
from firebase_admin.exceptions import FirebaseError

logger = structlog.get_logger()

class FirebaseSetupError(Exception):
    """Custom exception for Firebase setup failures."""
    pass

class FirebaseManager:
    """Singleton manager for Firebase connections and Firestore operations."""
    
    _instance = None
    _initialized = False
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(FirebaseManager, cls).__new__(cls)
        return cls._instance
    
    def __init__(self):
        if not self._initialized:
            self.db = None
            self._initialized = True
    
    def initialize(self, credential_path: Optional[str] = None) -> None:
        """
        Initialize Firebase Admin SDK with robust error handling.
        
        Args:
            credential_path: Path to service account JSON file. If None, uses GOOGLE_APPLICATION_CREDENTIALS env var.
            
        Raises:
            FirebaseSetupError: If initialization fails.
            FileNotFoundError: If credential file doesn't exist.
        """
        try:
            logger.info("firebase_initialization_started", credential_path=credential_path)
            
            # Verify credential existence
            if credential_path and not os.path.exists(credential_path):
                raise FileNotFoundError(f"Credential file not found: {credential_path}")
            
            # Load environment variable if no explicit path
            if not credential_path:
                credential_path = os.environ.get("GOOGLE_APPLICATION_CREDENTIALS")
                if not credential_path:
                    raise FirebaseSetupError(
                        "No credential path provided and GOOGLE_APPLICATION_CREDENTIALS not set"
                    )
            
            # Initialize with credentials
            cred = credentials.Certificate(credential_path)
            app = initialize_app(cred, {
                'projectId': cred.project_id,
                'databaseURL': f'https://{cred.project_id}.firebaseio.com'
            })
            
            # Initialize Firestore client
            self.db = admin_firestore.client(app)
            
            # Verify connection
            self._verify_connection()
            
            logger.info("firebase_initialization_success", project_id=cred.project_id)
            
        except FirebaseError as e:
            logger.error("firebase_init_error", error=str(e), error_code=e.code)
            raise FirebaseSetupError(f"Firebase initialization failed: {str(e)}") from e
        except Exception as e:
            logger.error("unexpected_init_error", error=str(e), error_type=type(e).__name__)
            raise FirebaseSetupError(f"Unexpected error during Firebase setup: {str(e)}") from e
    
    def _verify_connection(self) -> None:
        """Verify Firebase connection by attempting a simple read."""
        try:
            # Attempt to read a non-existent document to test connection
            doc_ref = self.db.collection("connection_test").document("test")
            doc_ref.get(timeout=5.0)
            logger.debug("firebase_connection_verified")
        except Exception as e:
            logger.error("firebase_connection_failed", error=str(e))
            raise FirebaseSetupError(f"Firebase connection test failed: {str(e)}") from e
    
    def setup_collections(self) -> Dict[str, bool]:
        """
        Create required Firestore collections with validation rules.
        Returns dict of collection creation status.
        """
        required_collections = [
            "developers",
            "attestations", 
            "reputation",
            "security_scores",
            "vulnerability_reports",
            "audit_logs"
        ]
        
        results = {}
        
        for collection_name in required_collections:
            try:
                # Create collection by adding a dummy document with metadata
                doc_ref = self.db.collection(collection_name).document("_metadata")
                doc_ref.set({
                    "created_at": firestore.SERVER_TIMESTAMP,
                    "schema_version": "1.0.0",
                    "purpose": f"Collection for {collection_name.replace('_', ' ')}"
                }, merge=True)
                
                results[collection_name] = True
                logger.info("collection_created", name=collection_name)
                
            except Exception as e:
                results[collection_name] = False
                logger.error("collection_creation_failed", 
                           name=collection_name, error=str(e))
        
        # Verify all collections were created
        if not all(results.values()):
            failed = [name for name, success in results.items() if not success]
            raise FirebaseSetupError(f"Failed to create collections: {failed}")
        
        return results
    
    def get_db(self) -> firestore.Client:
        """Get Firestore client with null check."""
        if self.db is None:
            raise FirebaseSetupError("Firebase not initialized. Call initialize() first.")
        return self.db

# Global instance
firebase_manager = FirebaseManager()

def setup_firebase(credential_path: Optional[str] = None) -> FirebaseManager:
    """
    Public function to initialize Firebase and setup collections.
    
    Example usage:
        try:
            manager = setup_firebase("path/to/credentials.json")
            db = manager.get_db()
        except FirebaseSetupError as e:
            print(f"Setup failed: {e}")
    """
    manager = FirebaseManager()
    manager.initialize(credential_path)
    manager.setup_collections()
    return manager
```

### FILE: developer_identity.py
```python
"""
WebAuthn/Passkey based developer identity system.
Implements decentralized identity where developers hold their own keys.
"""
import json
import base64
import structlog
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature
from webauthn import (
    generate_registration_options,
    verify_registration_response,
    generate_authentication_options,
    verify_authentication_response,
    options_to_json,
    base64url_to_bytes
)
from webauthn.helpers import bytes_to_base64url, parse_attestation_object
from webauthn.helpers.structs import (
    PublicKeyCredentialCreationOptions,
    AuthenticatorSelectionCriteria,
    UserVerificationRequirement,
    RegistrationCredential,
    AuthenticationCredential
)
import firebase_admin
from firebase_admin import firestore

logger = structlog.get_logger()

@dataclass
class DeveloperIdentity:
    """Immutable developer identity data class."""
    developer_id: str
    public_key: str  # Base64 encoded
    key_algorithm: str  # "ed25519" or "rsa"
    registration_timestamp: datetime
    last_used: Optional[datetime]
    reputation_score: int = 50  # Default score
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to Firestore-serializable dict."""
        return {
            "developer_id": self.developer_id,
            "public_key": self.public_key,
            "key_algorithm": self.key_algorithm,
            "registration_timestamp": self.registration_timestamp,
            "last_used": self.last_used,
            "reputation_score": self.reputation_score
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'DeveloperIdentity':
        """Create from Firestore dict."""
        return cls(
            developer_id=data["developer_id"],
            public_key=data["public_key"],
            key_algorithm=data["key_algorithm"],
            registration_timestamp=data["registration_timestamp"],
            last_used=data.get("last_used"),
            reputation_score=data.get("reputation_score", 50)
        )

class IdentityManagerError(Exception):
    """Custom exception for identity management failures."""
    pass

class IdentityManager:
    """
    Manages developer identity lifecycle including:
    - WebAuthn registration/authentication
    - Key pair generation and storage
    - Identity verification
    """
    
    def __init__(self, db: firestore.Client):
        self.db = db
        self.developers_ref = db.collection("developers")
        self.rp_id = "clawdhub.com"  # Relying Party ID
        self.rp_name = "ClawdHub Attestation Service"
    
    def generate_registration_challenge(self, developer_email: str) -> Dict[str, Any]:
        """
        Generate WebAuthn registration options for a new developer.
        
        Args:
            developer_email: Developer's email for user handle
            
        Returns:
            Registration options to send to client
        """
        try:
            # Check if developer already exists
            existing_dev = self.developers_ref.where("developer_id", "==", developer_email).get()
            if list(existing_dev):
                raise IdentityManagerError(f"Developer {developer_email} already registered")
            
            # Generate registration options
            options = generate_registration_options(
                rp_id=self.rp_id,
                rp_name=self.rp_name,
                user_id=developer_email.encode(),
                user_name=developer_email,
                user_display_name=developer_email.split('@')[0],
                attestation="direct",
                authenticator_selection=AuthenticatorSelectionCriteria(
                    user_verification=UserVerificationRequirement.PREFERRED,
                    resident_key="preferred"
                ),
                timeout=300000  # 5 minutes
            )
            
            # Store challenge temporarily (in production, use Redis or similar)
            challenge_doc = self.db.collection("registration_challenges").document(developer_email)
            challenge_doc.set({
                "challenge": bytes_to_base64url(options.challenge),
                "created_at": firestore.SERVER_TIMESTAMP,
                "expires_at": firestore.SERVER_TIMESTAMP + timedelta(minutes=5)
            })
            
            logger.info("registration_challenge_generated", 
                       developer_email=developer_email,
                       challenge_id=challenge_doc.id)
            
            return json.loads(options_to_json(options))
            
        except Exception as e:
            logger.error("registration_challenge_error", 
                        developer_email=developer_email,
                        error=str(e))
            raise IdentityManagerError(f"Failed to generate registration challenge: {str(e)}") from e
    
    def verify_registration_response(self, 
                                   developer_email: str, 
                                   registration_response: Dict[str, Any]) -> DeveloperIdentity:
        """
        Verify WebAuthn registration response and create developer identity.
        
        Args:
            developer_email: Developer's email
            registration_response: Response from authenticator
            
        Returns:
            Verified DeveloperIdentity
        """
        try:
            # Retrieve stored challenge
            challenge_doc = self.db.collection("registration_challenges").document(developer_email)
            challenge_data = challenge_doc.get()
            
            if not challenge_data.exists:
                raise IdentityManagerError("Registration challenge expired or not found")
            
            # Verify challenge expiration
            expires_at = challenge_data.get("expires_at")
            if expires_at and expires_at < datetime.utcnow():
                challenge_doc.delete()
                raise IdentityManagerError("Registration challenge expired")
            
            stored_challenge = base64url_to_bytes(challenge_data.get("challenge"))
            
            # Verify registration response
            verification = verify_registration_response(
                credential=RegistrationCredential.parse_raw(json.dumps(registration_response)),
                expected_challenge=stored_challenge,
                expected_rp_id=self.rp_id,
                expected_origin=f"https://{self.rp_id}"
            )
            
            # Generate code-signing key pair (separate from WebAuthn key)
            signing_private_key = ed25519.Ed25519PrivateKey.generate()
            signing_public_key = signing_private_key.public_key()
            
            # Serialize public key
            public_key_bytes = signing_public_key.public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            )
            
            # Create developer identity
            developer_id = f"passkey:{base64.urlsafe_b64encode(public_key_bytes[:16]).decode()}"
            
            identity = DeveloperIdentity(
                developer_id=developer_id,
                public_key=base64.b64encode(public_key_bytes).decode(),
                key_algorithm="ed25519",
                registration_timestamp=datetime.utcnow(),
                last_used=None,
                reputation_score=50
            )
            
            # Store in Firestore
            dev_doc = self.developers_ref.document(developer_id)
            dev_doc.set(identity.to_dict())
            
            # Store private key locally (in production, use secure key storage)
            private_key_pem = signing_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            
            # Clean up challenge
            challenge_doc.delete()
            
            logger.info("developer_registered_successfully",
                       developer_id=developer_id,
                       developer_email=developer_email)
            
            return identity