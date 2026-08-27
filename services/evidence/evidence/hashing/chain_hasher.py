"""
Blockchain-style chain hash for evidence integrity.
Detects if any finding was deleted or reordered.
"""

import hashlib
import logging
from typing import List, Optional


logger = logging.getLogger(__name__)


class ChainHasher:
    """
    Creates blockchain-style hash chain across findings.
    
    Formula:
        chain_hash[0] = SHA256(content_hash[0] + scan_session_id)
        chain_hash[N] = SHA256(content_hash[N] + chain_hash[N-1])
    
    Property:
    - Modifying any finding changes its content_hash
    - Which breaks all subsequent chain_hashes
    - Deleting/reordering findings also breaks chain
    """
    
    @staticmethod
    def compute_chain_hash(
        content_hash: str,
        previous_chain_hash: Optional[str] = None,
        scan_session_id: Optional[str] = None,
    ) -> str:
        if previous_chain_hash is None:
            chain_input = f"{content_hash}{scan_session_id or ''}"
        else:
            chain_input = f"{content_hash}{previous_chain_hash}"
        return hashlib.sha256(chain_input.encode("utf-8")).hexdigest()

    @staticmethod
    def compute_chain(
        content_hashes: List[str],
        scan_session_id: str
    ) -> List[str]:
        """
        Compute chain hashes for all findings.
        
        Args:
            content_hashes: List of SHA-256 content hashes in order
            scan_session_id: Unique scan session identifier
            
        Returns:
            List of chain hashes corresponding to findings
        """
        if not content_hashes:
            return []
        
        chain_hashes = []
        previous_hash = None
        
        for i, content_hash in enumerate(content_hashes):
            if i == 0:
                # First finding chains to scan session ID
                chain_input = f"{content_hash}{scan_session_id}"
            else:
                # Subsequent findings chain to previous hash
                chain_input = f"{content_hash}{previous_hash}"
            
            chain_hash = hashlib.sha256(
                chain_input.encode('utf-8')
            ).hexdigest()
            
            chain_hashes.append(chain_hash)
            previous_hash = chain_hash
        
        return chain_hashes
    
    @staticmethod
    def verify_chain(
        content_hashes: List[str],
        stored_chain_hashes: List[str],
        scan_session_id: str
    ) -> bool:
        """
        Verify entire chain is intact.
        
        Args:
            content_hashes: Current content hashes
            stored_chain_hashes: Previously stored chain hashes
            scan_session_id: Scan session ID
            
        Returns:
            True if chain is intact, False if tampering detected
        """
        if len(content_hashes) != len(stored_chain_hashes):
            logger.warning(
                f"Chain length mismatch: {len(content_hashes)} vs {len(stored_chain_hashes)}"
            )
            return False
        
        computed_chain = ChainHasher.compute_chain(content_hashes, scan_session_id)
        
        for i, (computed, stored) in enumerate(zip(computed_chain, stored_chain_hashes)):
            if computed != stored:
                logger.warning(
                    f"Chain hash mismatch at position {i}: "
                    f"expected {stored}, got {computed}"
                )
                return False
        
        return True
    
    @staticmethod
    def verify_single(
        content_hash: str,
        stored_chain_hash: str,
        previous_chain_hash: Optional[str],
        scan_session_id: Optional[str] = None
    ) -> bool:
        """
        Verify single link in chain (for incremental verification).
        
        Args:
            content_hash: Content hash of this finding
            stored_chain_hash: Expected chain hash
            previous_chain_hash: Previous finding's chain hash (None if first)
            scan_session_id: Scan session ID (required if first finding)
            
        Returns:
            True if link is valid, False if tampering detected
        """
        if previous_chain_hash is None and scan_session_id is None:
            logger.error("Either previous_chain_hash or scan_session_id required")
            return False
        
        if previous_chain_hash is None:
            chain_input = f"{content_hash}{scan_session_id}"
        else:
            chain_input = f"{content_hash}{previous_chain_hash}"
        
        computed_hash = hashlib.sha256(
            chain_input.encode('utf-8')
        ).hexdigest()
        
        if computed_hash != stored_chain_hash:
            logger.warning(
                f"Chain link invalid: expected {stored_chain_hash}, got {computed_hash}"
            )
            return False
        
        return True