# services/scanner/scanner/config/scanner_config.py

"""
Production scanner configuration management.
Uses Pydantic Settings for validation and environment variable loading.
"""

from typing import List, Set, Optional
from pathlib import Path
from pydantic import Field, validator
from shared_config.base_settings import BaseSettings


class ScannerConfig(BaseSettings):
    """
    Scanner service configuration.
    
    Environment variables override defaults:
    - SCANNER_JAVA_HOME: Path to JDK installation
    - SCANNER_TEMP_DIR: Temporary directory for scanning
    - SCANNER_EXCLUDE_DIRS: Comma-separated directory patterns to exclude
    - SCANNER_MAX_FILE_SIZE: Maximum file size to scan (bytes)
    - SCANNER_TIMEOUT_SECONDS: Scan timeout per repository
    """
    
    # JDK Configuration
    java_home: Optional[str] = Field(
        default=None,
        description="Path to JDK. Auto-detected if not set."
    )
    
    java_version: str = Field(
        default="11",
        description="Minimum Java version required"
    )
    
    # Scanner Paths
    temp_dir: Path = Field(
        default=Path("/tmp/cryptoscan"),
        description="Temporary directory for scanner workspace"
    )
    
    scanner_jar_path: Optional[Path] = Field(
        default=None,
        description="Path to compiled JDT scanner JAR. Required for production."
    )
    
    # File Discovery
    exclude_dirs: Set[str] = Field(
        default={
            "test", "tests", "testing",
            "build", "dist", "target",
            ".git", ".github", ".gradle", ".mvn",
            "node_modules", "venv", "env", ".venv",
            "__pycache__", ".pytest_cache",
        },
        description="Directory patterns to exclude from scanning"
    )
    
    exclude_extensions: Set[str] = Field(
        default={".class", ".o", ".pyc", ".pyo", ".so", ".dll", ".exe"},
        description="File extensions to exclude"
    )
    
    # File Size Limits
    max_file_size_bytes: int = Field(
        default=10 * 1024 * 1024,  # 10MB
        description="Maximum file size to scan (bytes)"
    )
    
    max_total_scan_size_bytes: int = Field(
        default=500 * 1024 * 1024,  # 500MB
        description="Maximum total scan size (bytes)"
    )
    
    # Timeout Settings
    scan_timeout_seconds: int = Field(
        default=600,  # 10 minutes
        description="Timeout per repository scan"
    )
    
    parser_timeout_seconds: int = Field(
        default=30,
        description="Timeout per Java file parsing"
    )
    
    # Language Support (extensible)
    supported_languages: Set[str] = Field(
        default={"java"},
        description="Supported programming languages. Week 2: Java only."
    )
    
    # Parallel Processing
    parser_threads: int = Field(
        default=4,
        description="Number of threads for parallel parsing"
    )
    
    # Logging
    log_level: str = Field(
        default="INFO",
        description="Python logging level"
    )
    
    log_file: Optional[Path] = Field(
        default=None,
        description="Log file path (stdout if not set)"
    )
    
    # Git Configuration
    git_shallow_clone: bool = Field(
        default=True,
        description="Use shallow clone (--depth 1) for faster cloning"
    )
    
    git_timeout_seconds: int = Field(
        default=120,
        description="Git clone timeout"
    )
    
    git_fetch_depth: int = Field(
        default=1,
        description="Git fetch depth for shallow clones"
    )
    
    class Config:
        env_prefix = "SCANNER_"
        case_sensitive = False
        
    @validator("temp_dir", pre=True)
    def validate_temp_dir(cls, v):
        """Ensure temp directory is creatable."""
        if v is None:
            v = Path("/tmp/cryptoscan")
        else:
            v = Path(v)
        
        # Create if doesn't exist
        v.mkdir(parents=True, exist_ok=True)
        return v
    
    @validator("scanner_jar_path", pre=True)
    def validate_scanner_jar(cls, v):
        """Validate scanner JAR exists in production."""
        if v is None:
            return None
        
        v = Path(v)
        if not v.exists():
            raise ValueError(f"Scanner JAR not found: {v}")
        
        if not v.suffix == ".jar":
            raise ValueError(f"Not a JAR file: {v}")
        
        return v
    
    @validator("scan_timeout_seconds", "parser_timeout_seconds", "git_timeout_seconds")
    def validate_timeouts(cls, v):
        """Ensure timeouts are positive."""
        if v <= 0:
            raise ValueError("Timeout must be positive")
        return v
    
    @validator("parser_threads")
    def validate_threads(cls, v):
        """Ensure reasonable thread count."""
        if v < 1 or v > 64:
            raise ValueError("Thread count must be 1-64")
        return v
    
    def get_excluded_dirs_pattern(self) -> str:
        """
        Build regex pattern from excluded directories.
        Returns: e.g., "(test|build|dist|.git|...)"
        """
        return "|".join(f"(?:^|/)({dir_})(?:/|$)" for dir_ in sorted(self.exclude_dirs))


# Singleton instance (lazy-loaded)
_config: Optional[ScannerConfig] = None

def get_config() -> ScannerConfig:
    """Get or create scanner configuration (singleton)."""
    global _config
    if _config is None:
        _config = ScannerConfig()
    return _config

def reload_config() -> ScannerConfig:
    """Force reload configuration (useful for testing)."""
    global _config
    _config = ScannerConfig()
    return _config