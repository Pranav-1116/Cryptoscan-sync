# services/database/db/connection/session.py

"""
Production-grade SQLAlchemy session factory.
Provides session management with context managers and dependency injection.
"""

from contextlib import contextmanager
from typing import Generator, Optional
from sqlalchemy.orm import sessionmaker, Session, declarative_base
from sqlalchemy.exc import SQLAlchemyError
import logging

logger = logging.getLogger(__name__)

# Base class for all ORM models
Base = declarative_base()


class SessionFactory:
    """
    Thread-safe session factory.
    Provides sessions with automatic cleanup and error handling.
    """
    
    _session_maker: Optional[sessionmaker] = None
    
    @classmethod
    def configure(cls, engine) -> None:
        """
        Configure session factory with SQLAlchemy engine.
        Must be called once before using get_session().
        
        Args:
            engine: SQLAlchemy Engine instance
        """
        cls._session_maker = sessionmaker(
            bind=engine,
            expire_on_commit=False,  # Don't expire objects after commit
            autoflush=True,  # Flush before queries
            autocommit=False,  # Require explicit commit
        )
        logger.info("SessionFactory configured")
    
    @classmethod
    def get_session(cls) -> Session:
        """
        Get a new database session.
        Use within context manager or explicitly close.
        
        Returns:
            SQLAlchemy Session
        
        Raises:
            RuntimeError: If SessionFactory not configured
        """
        if cls._session_maker is None:
            raise RuntimeError("SessionFactory not configured. Call configure() first.")
        
        session = cls._session_maker()
        logger.debug("Session created")
        return session
    
    @classmethod
    @contextmanager
    def session_scope(cls) -> Generator[Session, None, None]:
        """
        Context manager for database sessions.
        Automatically commits on success, rolls back on error.
        
        Usage:
            with SessionFactory.session_scope() as session:
                session.query(User).filter(...).first()
        
        Yields:
            SQLAlchemy Session
        
        Raises:
            SQLAlchemyError: On database errors
        """
        session = cls.get_session()
        
        try:
            yield session
            session.commit()
            logger.debug("Session committed")
        except SQLAlchemyError as e:
            session.rollback()
            logger.error(f"Database error, rolled back: {e}")
            raise
        except Exception as e:
            session.rollback()
            logger.error(f"Unexpected error, rolled back: {e}")
            raise
        finally:
            session.close()
            logger.debug("Session closed")
    
    @classmethod
    def create_all(cls, engine) -> None:
        """
        Create all tables defined in Base.metadata.
        DEPRECATED: Use Alembic migrations instead.
        Only for testing/development.
        """
        logger.warning("create_all() called. Use Alembic for production!")
        Base.metadata.create_all(bind=engine)


# Dependency injection function for FastAPI
def get_db_session() -> Generator[Session, None, None]:
    """
    Dependency for FastAPI routes.
    Provides session within request context.
    
    Usage in routes:
        @router.get("/users")
        def list_users(session: Session = Depends(get_db_session)):
            return session.query(User).all()
    
    Yields:
        SQLAlchemy Session
    """
    with SessionFactory.session_scope() as session:
        yield session


@contextmanager
def transactional_session(nested: bool = False) -> Generator[Session, None, None]:
    """
    Convenience context manager for transactional operations.
    
    Args:
        nested: If True, use nested transaction (savepoint)
    
    Yields:
        SQLAlchemy Session
    """
    session = SessionFactory.get_session()
    
    try:
        if nested and session.in_transaction():
            # Create savepoint
            savepoint = session.begin_nested()
            try:
                yield session
                savepoint.commit()
            except Exception:
                savepoint.rollback()
                raise
        else:
            yield session
            session.commit()
    except SQLAlchemyError as e:
        session.rollback()
        logger.error(f"Transaction failed: {e}")
        raise
    finally:
        session.close()