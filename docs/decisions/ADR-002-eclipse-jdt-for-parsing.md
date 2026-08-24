# ADR-002 Eclipse JDT for parsing

Production Java parsing should use Eclipse JDT. Part 1 ships a regex fallback so the platform runs without a JDK/JDT JAR. JDT sources are in `services/scanner/jdt/`.
