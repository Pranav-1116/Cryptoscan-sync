# services/worker/worker/workspace/workspace_manager.py

"""
Production workspace manager for isolated repository cloning and scanning.
Handles temporary directory lifecycle with cleanup and security.
"""

import os
import shutil
import tempfile
import logging
from pathlib import Path
from typing import Optional
from datetime import datetime

logger = logging.getLogger(__name__)


class WorkspaceManager:
    """
    Manages isolated workspace directories for scan jobs.
    Ensures cleanup and prevents resource leaks.
    """
    
    def __init__(self, base_temp_dir: str = "/tmp/cryptoscan"):
        """
        Initialize workspace manager.
        
        Args:
            base_temp_dir: Base directory for workspaces
        """
        self.base_temp_dir = Path(base_temp_dir)
        self.base_temp_dir.mkdir(parents=True, exist_ok=True)
        
        # Track active workspaces
        self.active_workspaces = {}
    
    async def create_workspace(self, scan_id: str) -> str:
        """
        Create isolated workspace for scan.
        
        Args:
            scan_id: Unique scan identifier
        
        Returns:
            Path to created workspace directory
        
        Raises:
            OSError: If workspace creation fails
        """
        try:
            # Create workspace with scan_id in name for traceability
            workspace_name = f"scan-{scan_id}-{datetime.utcnow().timestamp()}"
            workspace_path = self.base_temp_dir / workspace_name
            
            workspace_path.mkdir(parents=True, exist_ok=True)
            
            # Set restrictive permissions (owner only)
            workspace_path.chmod(0o700)
            
            # Track workspace
            self.active_workspaces[scan_id] = {
                "path": str(workspace_path),
                "created_at": datetime.utcnow(),
            }
            
            logger.info(
                f"Workspace created: {workspace_path} (scan: {scan_id})"
            )
            
            return str(workspace_path)
        
        except OSError as e:
            logger.error(f"Failed to create workspace for scan {scan_id}: {e}")
            raise
    
    async def get_workspace(self, scan_id: str) -> Optional[str]:
        """
        Get workspace path for scan (if exists).
        
        Args:
            scan_id: Scan identifier
        
        Returns:
            Workspace path or None if not created
        """
        workspace_info = self.active_workspaces.get(scan_id)
        
        if workspace_info:
            return workspace_info["path"]
        
        return None
    
    async def cleanup(self, workspace_path: str) -> None:
        """
        Delete workspace directory (recursive).
        Called after scan completion/failure.
        
        Args:
            workspace_path: Path to workspace to delete
        """
        try:
            workspace_path_obj = Path(workspace_path)
            
            if not workspace_path_obj.exists():
                logger.warning(f"Workspace not found: {workspace_path}")
                return
            
            # Verify it's under base_temp_dir (safety check)
            try:
                workspace_path_obj.relative_to(self.base_temp_dir)
            except ValueError:
                logger.error(
                    f"Workspace path not under base directory: {workspace_path}"
                )
                return
            
            # Remove recursively
            shutil.rmtree(workspace_path_obj)
            
            # Remove from tracking
            for scan_id, info in list(self.active_workspaces.items()):
                if info["path"] == workspace_path:
                    del self.active_workspaces[scan_id]
                    break
            
            logger.info(f"Workspace cleaned up: {workspace_path}")
        
        except Exception as e:
            logger.error(f"Workspace cleanup error: {workspace_path}: {e}")
    
    async def cleanup_all(self) -> None:
        """
        Emergency cleanup: remove all active workspaces.
        Called on service shutdown.
        """
        for scan_id, info in list(self.active_workspaces.items()):
            try:
                await self.cleanup(info["path"])
            except Exception as e:
                logger.error(
                    f"Failed to cleanup workspace for scan {scan_id}: {e}"
                )
    
    async def get_workspace_size(self, workspace_path: str) -> int:
        """
        Calculate total size of workspace directory.
        
        Args:
            workspace_path: Workspace path
        
        Returns:
            Size in bytes
        """
        try:
            total_size = 0
            for dirpath, dirnames, filenames in os.walk(workspace_path):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    if os.path.isfile(filepath):
                        total_size += os.path.getsize(filepath)
            return total_size
        except Exception as e:
            logger.error(f"Failed to calculate workspace size: {e}")
            return 0
    
    async def enforce_workspace_limit(
        self,
        workspace_path: str,
        limit_bytes: int = 5 * 1024 * 1024 * 1024  # 5GB default
    ) -> bool:
        """
        Enforce maximum workspace size.
        
        Args:
            workspace_path: Workspace to check
            limit_bytes: Maximum allowed size
        
        Returns:
            True if under limit, False if exceeded
        """
        size = await self.get_workspace_size(workspace_path)
        
        if size > limit_bytes:
            logger.warning(
                f"Workspace size limit exceeded: "
                f"{size / 1024 / 1024 / 1024:.2f}GB / "
                f"{limit_bytes / 1024 / 1024 / 1024:.2f}GB"
            )
            return False
        
        return True