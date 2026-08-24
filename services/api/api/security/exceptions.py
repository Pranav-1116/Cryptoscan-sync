"""
Security Exceptions - Custom exception types.

Domain-specific exceptions for security and validation.
"""

from typing import Optional, List, Dict, Any


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    
    def __init__(
        self,
        message: str,
        error_code: str = "AUTHENTICATION_FAILED"
    ):
        """
        Initialize exception.
        
        Args:
            message: Error message
            error_code: Machine-readable error code
        """
        self.message = message
        self.error_code = error_code
        super().__init__(self.message)


class AuthorizationError(Exception):
    """Raised when user lacks required permissions."""
    
    def __init__(
        self,
        message: str,
        required_roles: Optional[List[str]] = None
    ):
        """
        Initialize exception.
        
        Args:
            message: Error message
            required_roles: Required roles for operation
        """
        self.message = message
        self.required_roles = required_roles or []
        super().__init__(self.message)


class ValidationError(Exception):
    """Raised when request validation fails."""
    
    def __init__(
        self,
        message: str,
        errors: Optional[Dict[str, Any]] = None
    ):
        """
        Initialize exception.
        
        Args:
            message: Error message
            errors: Detailed error information
        """
        self.message = message
        self.errors = errors or {}
        super().__init__(self.message)


class NotFoundError(Exception):
    """Raised when resource not found."""
    
    def __init__(self, resource_type: str, resource_id: str):
        """
        Initialize exception.
        
        Args:
            resource_type: Type of resource (e.g., "Scan", "Finding")
            resource_id: ID of resource
        """
        self.resource_type = resource_type
        self.resource_id = resource_id
        self.message = f"{resource_type} not found: {resource_id}"
        super().__init__(self.message)


class ConflictError(Exception):
    """Raised when operation conflicts with existing state."""
    
    def __init__(self, message: str):
        """
        Initialize exception.
        
        Args:
            message: Error message
        """
        self.message = message
        super().__init__(self.message)