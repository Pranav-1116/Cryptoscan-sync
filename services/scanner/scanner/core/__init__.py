"""Scanner core: orchestration, file discovery, language detection.

Modules:
- file_discovery: File discovery - walk directory tree and find Java source files
- language_detector: Detect source languages present in a repository
- multi_language_runner: Run language-specific detectors over a discovered file set
- plugin: Discovery plugin contract. Scanners implement this; the worker orchestrates
- scan_context: Metadata for one scanner run
- scanner: Static scanner orchestrator — single public API used by CLI and worker
"""
