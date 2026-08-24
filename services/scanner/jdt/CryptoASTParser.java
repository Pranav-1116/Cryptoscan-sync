package com.cryptoscan.scanner.jdt;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.*;
import org.eclipse.jdt.core.*;
import org.eclipse.jdt.core.dom.*;

/**
 * Production-grade Java AST parser using Eclipse JDT.
 * Parses Java source files and builds Abstract Syntax Trees for crypto analysis.
 * 
 * Thread-safe: Each parser instance must be used by a single thread.
 */
public class CryptoASTParser {
    
    private static final String JDT_VERSION = "4.26";
    private final ASTParser astParser;
    private final Map<String, String> compilerOptions;
    
    /**
     * Initialize with production compiler settings.
     */
    public CryptoASTParser() {
        this.astParser = ASTParser.newParser(AST.JLS_Latest);
        this.compilerOptions = initializeCompilerOptions();
    }
    
    /**
     * Parse a single Java source file into CompilationUnit (AST root).
     * 
     * @param sourceFile Path to .java file
     * @param sourceEncoding Character encoding (default: UTF-8)
     * @return CompilationUnit AST, or null if parse fails
     * @throws IllegalArgumentException if file doesn't exist or isn't readable
     */
    public CompilationUnit parseFile(File sourceFile, String sourceEncoding) {
        if (!sourceFile.exists()) {
            throw new IllegalArgumentException("Source file not found: " + sourceFile.getAbsolutePath());
        }
        
        if (!sourceFile.isFile() || !sourceFile.getName().endsWith(".java")) {
            throw new IllegalArgumentException("Not a valid Java file: " + sourceFile.getName());
        }
        
        try {
            String charset = sourceEncoding != null ? sourceEncoding : StandardCharsets.UTF_8.name();
            byte[] fileBytes = Files.readAllBytes(sourceFile.toPath());
            String sourceCode = new String(fileBytes, charset);
            
            return parseSource(sourceCode, sourceFile.getAbsolutePath());
        } catch (Exception e) {
            // Log and return null — graceful degradation
            System.err.printf("Parse error in %s: %s%n", sourceFile.getName(), e.getMessage());
            return null;
        }
    }
    
    /**
     * Parse raw source code string into CompilationUnit.
     * 
     * @param sourceCode Java source code as String
     * @param sourceLocation File path (for debugging, doesn't affect parsing)
     * @return CompilationUnit AST
     */
    public CompilationUnit parseSource(String sourceCode, String sourceLocation) {
        this.astParser.setSource(sourceCode.toCharArray());
        this.astParser.setKind(ASTParser.K_COMPILATION_UNIT);
        this.astParser.setCompilerOptions(compilerOptions);
        this.astParser.setResolveBindings(false); // Performance: don't resolve bindings
        this.astParser.setBindingsRecovery(true); // Continue on missing types
        
        try {
            CompilationUnit cu = (CompilationUnit) astParser.createAST(null);
            // Capture parse problems for logging
            IProblem[] problems = cu.getProblems();
            if (problems.length > 0) {
                System.err.printf("Parse warnings in %s: %d problems%n", sourceLocation, problems.length);
                for (IProblem p : problems) {
                    if (p.isError()) {
                        System.err.printf("  ERROR [%d:%d] %s%n", p.getSourceLineNumber(), 
                            p.getSourceStart(), p.getMessage());
                    }
                }
            }
            return cu;
        } catch (Exception e) {
            System.err.printf("AST creation failed for %s: %s%n", sourceLocation, e.getMessage());
            return null;
        }
    }
    
    /**
     * Extract all types (classes, interfaces) from compilation unit.
     * 
     * @param cu CompilationUnit to analyze
     * @return List of AbstractTypeDeclaration (classes, interfaces, enums)
     */
    public List<AbstractTypeDeclaration> extractTypeDeclarations(CompilationUnit cu) {
        List<AbstractTypeDeclaration> types = new ArrayList<>();
        
        if (cu == null) {
            return types;
        }
        
        for (Object obj : cu.types()) {
            if (obj instanceof AbstractTypeDeclaration) {
                types.add((AbstractTypeDeclaration) obj);
            }
        }
        
        return types;
    }
    
    /**
     * Get package name from compilation unit.
     * 
     * @param cu CompilationUnit
     * @return Fully-qualified package name, or "" if default package
     */
    public String getPackageName(CompilationUnit cu) {
        if (cu == null) {
            return "";
        }
        
        PackageDeclaration pkg = cu.getPackage();
        if (pkg == null) {
            return ""; // Default package
        }
        
        return pkg.getName().getFullyQualifiedName();
    }
    
    /**
     * Get source file line content by line number.
     * Used for extracting code snippets around findings.
     * 
     * @param sourceCode Full source code
     * @param lineNumber 1-indexed line number
     * @param contextLines Number of lines before/after to include
     * @return List of lines with context (empty if line out of range)
     */
    public List<String> getCodeSnippet(String sourceCode, int lineNumber, int contextLines) {
        String[] lines = sourceCode.split("\n", -1);
        List<String> snippet = new ArrayList<>();
        
        int startLine = Math.max(0, lineNumber - 1 - contextLines);
        int endLine = Math.min(lines.length, lineNumber + contextLines);
        
        for (int i = startLine; i < endLine; i++) {
            snippet.add(lines[i]);
        }
        
        return snippet;
    }
    
    /**
     * Initialize JDT compiler options for Java parsing.
     * Production settings: Java 11+ compatibility, error recovery enabled.
     */
    private Map<String, String> initializeCompilerOptions() {
        Map<String, String> options = JavaCore.getDefaultOptions();
        
        // Set language level to Java 11 minimum (covers modern codebases)
        options.put(JavaCore.COMPILER_SOURCE, "11");
        options.put(JavaCore.COMPILER_CODEGEN_TARGET_PLATFORM, "11");
        options.put(JavaCore.COMPILER_COMPLIANCE, "11");
        
        // Error recovery: parse even with missing/invalid code
        options.put(JavaCore.COMPILER_PB_MISSING_OVERRIDE_ANNOTATION, JavaCore.IGNORE);
        options.put(JavaCore.COMPILER_PB_MISSING_SERIAL_VERSION_UID_FIELD_FOR_SERIALIZABLE_CLASS, 
            JavaCore.IGNORE);
        
        // Warnings off for production (we log them separately)
        options.put(JavaCore.COMPILER_PB_UNCHECKED_TYPE_OPERATION, JavaCore.IGNORE);
        options.put(JavaCore.COMPILER_PB_RAW_TYPE_REFERENCE, JavaCore.IGNORE);
        
        return options;
    }
    
    /**
     * Validate that a file is a valid Java source file.
     * Quick check before parsing to fail fast.
     */
    public static boolean isValidJavaFile(File file) {
        return file.isFile() 
            && file.getName().endsWith(".java") 
            && file.canRead() 
            && file.length() > 0;
    }
}