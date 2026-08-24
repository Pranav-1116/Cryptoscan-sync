"""
Logging Context
Thread-local context for adding fields to all logs
"""
import threading
import logging
from typing import Optional, Dict, Any

# Thread-local storage for context
_context = threading.local()


def set_request_context(request_id: str, **kwargs):
    """
    Set request context for logging
    All subsequent logs will include request_id
    """
    if not hasattr(_context, 'data'):
        _context.data = {}
    
    _context.data['request_id'] = request_id
    _context.data.update(kwargs)


def set_scan_context(scan_id: str, **kwargs):
    """
    Set scan context for logging
    """
    if not hasattr(_context, 'data'):
        _context.data = {}
    
    _context.data['scan_id'] = scan_id
    _context.data.update(kwargs)


def set_job_context(job_id: str, **kwargs):
    """
    Set job context for logging
    """
    if not hasattr(_context, 'data'):
        _context.data = {}
    
    _context.data['job_id'] = job_id
    _context.data.update(kwargs)


def get_context() -> Dict[str, Any]:
    """Get current logging context"""
    if not hasattr(_context, 'data'):
        return {}
    return _context.data.copy()


def clear_context():
    """Clear logging context"""
    if hasattr(_context, 'data'):
        _context.data.clear()


class ContextFilter(logging.Filter):
    """
    Logging filter that adds context to log records
    """
    
    def filter(self, record: logging.LogRecord) -> bool:
        """Add context fields to record"""
        if hasattr(_context, 'data'):
            for key, value in _context.data.items():
                setattr(record, key, value)
        return True


def add_context_to_logger(logger: logging.Logger):
    """
    Add context filter to logger
    """
    logger.addFilter(ContextFilter())