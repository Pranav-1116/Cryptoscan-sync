"""
Repository Configuration Repository
CRUD operations for repo configurations
"""
import logging
from typing import Optional, List
from sqlalchemy.orm import Session

from ..models.repo_configuration import RepoConfiguration
from .base_repository import BaseRepository

logger = logging.getLogger(__name__)


class RepoConfigRepository(BaseRepository[RepoConfiguration]):
    """Repository for RepoConfiguration model"""
    
    def __init__(self, db: Session):
        super().__init__(RepoConfiguration, db)
    
    def create(
        self,
        repo_url: str,
        repo_name: str,
        enabled: bool = True,
        scan_on_push: bool = True,
        scan_on_pr: bool = False,
        notification_emails: Optional[List[str]] = None
    ) -> RepoConfiguration:
        """Create repository configuration"""
        config = RepoConfiguration(
            repo_url=repo_url,
            repo_name=repo_name,
            enabled=enabled,
            scan_on_push=scan_on_push,
            scan_on_pr=scan_on_pr,
            notification_emails=notification_emails or []
        )
        
        self.db.add(config)
        self.db.commit()
        self.db.refresh(config)
        
        logger.info(f"Created repo config for {repo_name}")
        return config
    
    def get_by_repo_url(self, repo_url: str) -> Optional[RepoConfiguration]:
        """Get config by repository URL"""
        return self.db.query(RepoConfiguration)\
            .filter(RepoConfiguration.repo_url == repo_url)\
            .first()
    
    def get_enabled_repos(self) -> List[RepoConfiguration]:
        """Get all enabled repository configurations"""
        return self.db.query(RepoConfiguration)\
            .filter(RepoConfiguration.enabled == True)\
            .all()
    
    def update_baseline(
        self,
        repo_url: str,
        baseline_scan_id: str
    ):
        """Update baseline scan for repository"""
        config = self.get_by_repo_url(repo_url)
        if not config:
            raise ValueError(f"Repo config not found for {repo_url}")
        
        config.baseline_scan_id = baseline_scan_id
        self.db.commit()
        logger.info(f"Updated baseline for {repo_url}")
    
    def is_scan_enabled(self, repo_url: str, event_type: str) -> bool:
        """
        Check if scanning is enabled for repo/event
        event_type: 'push' or 'pull_request'
        """
        config = self.get_by_repo_url(repo_url)
        if not config or not config.enabled:
            return False
        
        if event_type == "push":
            return config.scan_on_push
        elif event_type == "pull_request":
            return config.scan_on_pr
        
        return False