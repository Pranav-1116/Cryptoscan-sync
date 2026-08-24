package com.cryptoscan.scanner.jdt;

import java.util.HashMap;
import java.util.Map;

/**
 * Production pattern matcher for cryptographic APIs.
 * Maps class/method combinations to crypto patterns (Cipher, MessageDigest, etc.).
 */
public class CryptoPatternMatcher {
    
    private final Map<String, Map<String, PatternMetadata>> patterns = new HashMap<>();
    
    public CryptoPatternMatcher() {
        initializePatterns();
    }
    
    /**
     * Initialize all recognized crypto patterns.
     * PRODUCTION: Update this based on your threat model and scope.
     */
    private void initializePatterns() {
        // PATTERN 1: javax.crypto.Cipher
        patterns.computeIfAbsent("Cipher", k -> new HashMap<>())
            .put("getInstance", new PatternMetadata(
                "CIPHER_INSTANCE",
                "ENCRYPTION",
                CryptoType.SYMMETRIC
            ));
        
        // PATTERN 2: java.security.MessageDigest
        patterns.computeIfAbsent("MessageDigest", k -> new HashMap<>())
            .put("getInstance", new PatternMetadata(
                "MESSAGE_DIGEST",
                "HASHING",
                CryptoType.HASH
            ));
        
        // PATTERN 3: javax.crypto.KeyGenerator
        patterns.computeIfAbsent("KeyGenerator", k -> new HashMap<>())
            .put("getInstance", new PatternMetadata(
                "KEY_GENERATOR",
                "KEY_GENERATION",
                CryptoType.KEY_AGREEMENT
            ));
        
        // PATTERN 4: java.security.Signature
        patterns.computeIfAbsent("Signature", k -> new HashMap<>())
            .put("getInstance", new PatternMetadata(
                "SIGNATURE_INSTANCE",
                "SIGNING",
                CryptoType.SIGNATURE
            ));
        
        // Add javax.crypto.Mac for HMAC
        patterns.computeIfAbsent("Mac", k -> new HashMap<>())
            .put("getInstance", new PatternMetadata(
                "MAC_INSTANCE",
                "AUTHENTICATION",
                CryptoType.MAC
            ));
        
        // Add javax.crypto.KeyAgreement
        patterns.computeIfAbsent("KeyAgreement", k -> new HashMap<>())
            .put("getInstance", new PatternMetadata(
                "KEY_AGREEMENT",
                "KEY_EXCHANGE",
                CryptoType.KEY_AGREEMENT
            ));
    }
    
    /**
     * Check if a receiver/method combination matches a known crypto pattern.
     * 
     * @param receiver Class name (e.g., "Cipher", "MessageDigest")
     * @param method Method name (e.g., "getInstance")
     * @return Match metadata if pattern found, null otherwise
     */
    public Match match(String receiver, String method) {
        if (receiver == null || method == null) {
            return null;
        }
        
        // Direct match (simple name)
        Map<String, PatternMetadata> methodMap = patterns.get(receiver);
        if (methodMap != null && methodMap.containsKey(method)) {
            return new Match(receiver, method, methodMap.get(method));
        }
        
        // Qualified name match (e.g., "javax.crypto.Cipher")
        for (String classPattern : patterns.keySet()) {
            if (receiver.endsWith("." + classPattern) || receiver.equals(classPattern)) {
                methodMap = patterns.get(classPattern);
                if (methodMap != null && methodMap.containsKey(method)) {
                    return new Match(receiver, method, methodMap.get(method));
                }
            }
        }
        
        return null;
    }
    
    /**
     * Match result: contains pattern metadata.
     */
    public static class Match {
        private final String receiver;
        private final String method;
        private final PatternMetadata metadata;
        
        public Match(String receiver, String method, PatternMetadata metadata) {
            this.receiver = receiver;
            this.method = method;
            this.metadata = metadata;
        }
        
        public String getApiType() { return metadata.apiType; }
        public String getPurpose() { return metadata.purpose; }
        public CryptoType getCryptoType() { return metadata.cryptoType; }
    }
    
    /**
     * Pattern metadata container.
     */
    private static class PatternMetadata {
        final String apiType;
        final String purpose;
        final CryptoType cryptoType;
        
        PatternMetadata(String apiType, String purpose, CryptoType cryptoType) {
            this.apiType = apiType;
            this.purpose = purpose;
            this.cryptoType = cryptoType;
        }
    }
    
    /**
     * Enum for crypto types (symmetric, asymmetric, etc.).
     */
    public enum CryptoType {
        SYMMETRIC,
        ASYMMETRIC,
        HASH,
        SIGNATURE,
        MAC,
        KEY_AGREEMENT
    }
}