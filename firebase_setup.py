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