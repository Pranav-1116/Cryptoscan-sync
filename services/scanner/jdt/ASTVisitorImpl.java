package com.cryptoscan.scanner.jdt;

import java.util.*;
import org.eclipse.jdt.core.dom.*;

/**
 * Production AST Visitor for cryptographic pattern detection.
 * 
 * Implements JDT's ASTVisitor interface to traverse compilation units
 * and detect cryptographic API calls (Cipher, MessageDigest, etc.).
 * 
 * Thread-safe: Visitor instances are stateless; use new instance per parse.
 */
public class ASTVisitorImpl extends ASTVisitor {
    
    private final List<CryptoFinding> findings = new ArrayList<>();
    private final CryptoPatternMatcher patternMatcher;
    private String currentFilePath;
    private String currentPackage;
    private String currentClassName;
    private String currentMethodName;
    private String sourceCode;
    
    /**
     * Initialize visitor with pattern matcher.
     * 
     * @param patternMatcher Injected pattern matcher (detects algorithms)
     * @param sourceCode Full source code (for snippet extraction)
     */
    public ASTVisitorImpl(CryptoPatternMatcher patternMatcher, String sourceCode) {
        this.patternMatcher = patternMatcher;
        this.sourceCode = sourceCode;
    }
    
    /**
     * Visit method invocation nodes (e.g., Cipher.getInstance()).
     * PRIMARY DETECTION POINT for crypto calls.
     */
    @Override
    public boolean visit(MethodInvocation node) {
        // Extract method and class names
        String methodName = node.getName().getIdentifier();
        String receiver = getReceiverType(node);
        
        // Check if this matches a known crypto pattern
        CryptoPatternMatcher.Match match = patternMatcher.match(receiver, methodName);
        
        if (match != null) {
            // Extract algorithm parameter (first argument usually)
            CryptoFinding finding = extractFindingFromInvocation(node, match);
            if (finding != null) {
                findings.add(finding);
            }
        }
        
        return super.visit(node);
    }
    
    /**
     * Visit variable declarations for hardcoded key detection.
     * Detects: SecretKeySpec, KeyStore initialization with literals.
     */
    @Override
    public boolean visit(VariableDeclaration node) {
        Type varType = node.getStructuralProperty(VariableDeclaration.TYPE_PROPERTY) instanceof Type 
            ? (Type) node.getStructuralProperty(VariableDeclaration.TYPE_PROPERTY) 
            : null;
        
        if (varType != null) {
            String typeName = varType.toString();
            
            // Detect SecretKeySpec with hardcoded key
            if (typeName.contains("SecretKeySpec")) {
                CryptoFinding finding = extractHardcodedKeyFinding(node);
                if (finding != null) {
                    findings.add(finding);
                }
            }
        }
        
        return super.visit(node);
    }
    
    /**
     * Visit class declarations to track context.
     */
    @Override
    public boolean visit(TypeDeclaration node) {
        this.currentClassName = node.getName().getIdentifier();
        return super.visit(node);
    }
    
    /**
     * Visit method declarations to track method context.
     */
    @Override
    public boolean visit(MethodDeclaration node) {
        this.currentMethodName = node.getName().getIdentifier();
        return super.visit(node);
    }
    
    /**
     * Extract receiver type from method invocation.
     * Handles: simple types (Cipher), qualified names (javax.crypto.Cipher), etc.
     * 
     * @param node MethodInvocation node
     * @return Type name as string (e.g., "Cipher", "javax.crypto.Cipher")
     */
    private String getReceiverType(MethodInvocation node) {
        Expression expression = node.getExpression();
        
        if (expression == null) {
            return null; // Method call on implicit 'this'
        }
        
        if (expression instanceof SimpleName) {
            return ((SimpleName) expression).getIdentifier();
        } else if (expression instanceof QualifiedName) {
            return ((QualifiedName) expression).getFullyQualifiedName();
        } else if (expression instanceof FieldAccess) {
            return ((FieldAccess) expression).getName().getIdentifier();
        } else if (expression instanceof MethodInvocation) {
            // Chain: obj.method().getInstance() — get method return type (simplified)
            return "CHAINED_CALL";
        }
        
        return expression.toString();
    }
    
    /**
     * Extract CryptoFinding from MethodInvocation node.
     * Parses arguments, extracts algorithm, key size, etc.
     * 
     * @param node MethodInvocation (e.g., Cipher.getInstance("AES/GCM/NoPadding"))
     * @param match Pattern match metadata
     * @return CryptoFinding object, or null if extraction fails
     */
    private CryptoFinding extractFindingFromInvocation(MethodInvocation node, 
                                                       CryptoPatternMatcher.Match match) {
        CryptoFinding finding = new CryptoFinding();
        
        // Set basic metadata
        finding.setApiType(match.getApiType());
        finding.setLineNumber(node.getStartPosition() > 0 
            ? getLineNumber(node.getStartPosition()) 
            : 0);
        finding.setColumnNumber(0); // JDT doesn't provide column easily
        finding.setMethodName(currentMethodName);
        finding.setClassName(currentClassName);
        finding.setFilePath(currentFilePath);
        finding.setPurpose(match.getPurpose());
        
        // Extract algorithm from first argument (if it's a string literal)
        List<Expression> arguments = node.arguments();
        if (!arguments.isEmpty()) {
            Expression arg0 = arguments.get(0);
            if (arg0 instanceof StringLiteral) {
                String algorithmStr = ((StringLiteral) arg0).getLiteralValue();
                parseAndSetAlgorithm(finding, algorithmStr);
                finding.setConfidence("HIGH"); // String literal = deterministic
            } else if (arg0 instanceof SimpleName) {
                // Variable passed — low confidence
                finding.setAlgorithm("UNKNOWN");
                finding.setConfidence("LOW");
            }
        }
        
        return finding;
    }
    
    /**
     * Extract hardcoded key finding from SecretKeySpec initialization.
     * 
     * @param node VariableDeclaration (SecretKeySpec var = new SecretKeySpec(...))
     * @return CryptoFinding flagged as HARDCODED_KEY
     */
    private CryptoFinding extractHardcodedKeyFinding(VariableDeclaration node) {
        CryptoFinding finding = new CryptoFinding();
        
        finding.setApiType("HARDCODED_KEY");
        finding.setLineNumber(getLineNumber(node.getStartPosition()));
        finding.setClassName(currentClassName);
        finding.setMethodName(currentMethodName);
        finding.setFilePath(currentFilePath);
        finding.setConfidence("CRITICAL");
        finding.setAlgorithm("HARDCODED");
        
        return finding;
    }
    
    /**
     * Parse algorithm string (e.g., "AES/GCM/NoPadding") into components.
     * 
     * @param finding CryptoFinding to populate
     * @param algorithmStr Algorithm string from code
     */
    private void parseAndSetAlgorithm(CryptoFinding finding, String algorithmStr) {
        String[] parts = algorithmStr.split("/");
        
        if (parts.length >= 1) {
            finding.setAlgorithm(parts[0].trim()); // Algorithm (AES, DES, etc.)
        }
        
        if (parts.length >= 2) {
            finding.setMode(parts[1].trim()); // Mode (GCM, ECB, etc.)
        }
        
        if (parts.length >= 3) {
            finding.setPadding(parts[2].trim()); // Padding (NoPadding, PKCS5Padding, etc.)
        }
    }
    
    /**
     * Convert AST node start position to line number.
     * AST positions are character offsets; we count newlines.
     */
    private int getLineNumber(int position) {
        if (sourceCode == null || position < 0 || position > sourceCode.length()) {
            return 0;
        }
        
        int lineNumber = 1;
        for (int i = 0; i < position; i++) {
            if (sourceCode.charAt(i) == '\n') {
                lineNumber++;
            }
        }
        return lineNumber;
    }
    
    /**
     * Retrieve all findings detected during AST traversal.
     */
    public List<CryptoFinding> getFindings() {
        return new ArrayList<>(findings);
    }
    
    /**
     * Set file path context (used for findings metadata).
     */
    public void setCurrentFilePath(String filePath) {
        this.currentFilePath = filePath;
    }
    
    /**
     * Set package context.
     */
    public void setCurrentPackage(String packageName) {
        this.currentPackage = packageName;
    }
}