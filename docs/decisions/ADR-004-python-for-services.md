# ADR-004 Python for services

All control-plane services are Python 3.11 (FastAPI, SQLAlchemy, Pydantic v2). The Java parser is the only JVM-facing piece and is invoked as a library or future subprocess.
