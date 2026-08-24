package com.cryptoscan.scanner.jdt;

/**
 * Production data class for cryptographic findings detected in AST.
 * Immutable (or use builder pattern) for thread-safety.
 */
public class CryptoFinding {
    
    private String apiType;          // CIPHER_INSTANCE, MESSAGE_DIGEST, etc.
    private String algorithm;        // AES, DES, RSA, SHA-256, etc.
    private String mode;             // GCM, ECB, CBC, etc. (nullable)
    private String padding;          // NoPadding, PKCS5Padding, etc. (nullable)
    private Integer keySize;         // 128, 256, 2048, etc. (nullable)
    private String purpose;          // ENCRYPTION, HASHING, SIGNING, etc.
    private String confidence;       // HIGH, MEDIUM, LOW
    private Integer lineNumber;
    private Integer columnNumber;
    private String className;        // Fully-qualified class name
    private String methodName;       // Method containing crypto call
    private String filePath;         // Relative path to source file
    
    // Getters and setters
    public String getApiType() { return apiType; }
    public void setApiType(String apiType) { this.apiType = apiType; }
    
    public String getAlgorithm() { return algorithm; }
    public void setAlgorithm(String algorithm) { this.algorithm = algorithm; }
    
    public String getMode() { return mode; }
    public void setMode(String mode) { this.mode = mode; }
    
    public String getPadding() { return padding; }
    public void setPadding(String padding) { this.padding = padding; }
    
    public Integer getKeySize() { return keySize; }
    public void setKeySize(Integer keySize) { this.keySize = keySize; }
    
    public String getPurpose() { return purpose; }
    public void setPurpose(String purpose) { this.purpose = purpose; }
    
    public String getConfidence() { return confidence; }
    public void setConfidence(String confidence) { this.confidence = confidence; }
    
    public Integer getLineNumber() { return lineNumber; }
    public void setLineNumber(Integer lineNumber) { this.lineNumber = lineNumber; }
    
    public Integer getColumnNumber() { return columnNumber; }
    public void setColumnNumber(Integer columnNumber) { this.columnNumber = columnNumber; }
    
    public String getClassName() { return className; }
    public void setClassName(String className) { this.className = className; }
    
    public String getMethodName() { return methodName; }
    public void setMethodName(String methodName) { this.methodName = methodName; }
    
    public String getFilePath() { return filePath; }
    public void setFilePath(String filePath) { this.filePath = filePath; }
    
    @Override
    public String toString() {
        return String.format("CryptoFinding{%s:%s [%s] @ %s:%d in %s.%s}",
            apiType, algorithm, confidence, filePath, lineNumber, className, methodName);
    }
}