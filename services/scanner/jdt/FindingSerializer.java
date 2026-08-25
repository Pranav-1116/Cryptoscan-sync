package com.cryptoscan.scanner.jdt;

import java.io.IOException;
import java.io.Writer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Serialize {@link CryptoFinding} records to the same JSON shape the Python
 * scanner emits so JDT output can feed the evidence pipeline unchanged.
 */
public final class FindingSerializer {

    private FindingSerializer() {}

    public static String toJson(List<CryptoFinding> findings) {
        StringBuilder out = new StringBuilder();
        out.append("{\"scanner_id\":\"static-java-jdt-scanner-v1.0\",\"findings\":[");
        List<CryptoFinding> rows = findings == null ? new ArrayList<>() : findings;
        for (int i = 0; i < rows.size(); i++) {
            if (i > 0) {
                out.append(',');
            }
            appendFinding(out, rows.get(i));
        }
        out.append("]}");
        return out.toString();
    }

    public static void write(Path path, List<CryptoFinding> findings) throws IOException {
        Files.writeString(path, toJson(findings), StandardCharsets.UTF_8);
    }

    public static void write(Writer writer, List<CryptoFinding> findings) throws IOException {
        writer.write(toJson(findings));
    }

    private static void appendFinding(StringBuilder out, CryptoFinding finding) {
        out.append('{');
        field(out, "api_type", finding.getApiType(), true);
        field(out, "algorithm", finding.getAlgorithm(), false);
        field(out, "mode", finding.getMode(), false);
        field(out, "padding", finding.getPadding(), false);
        if (finding.getKeySize() != null) {
            out.append(",\"key_size\":").append(finding.getKeySize());
        }
        field(out, "purpose", finding.getPurpose(), false);
        field(out, "confidence", finding.getConfidence(), false);
        if (finding.getLineNumber() != null) {
            out.append(",\"line_number\":").append(finding.getLineNumber());
        }
        if (finding.getColumnNumber() != null) {
            out.append(",\"column_number\":").append(finding.getColumnNumber());
        }
        field(out, "class_name", finding.getClassName(), false);
        field(out, "method_name", finding.getMethodName(), false);
        field(out, "file_path", finding.getFilePath(), false);
        out.append('}');
    }

    private static void field(StringBuilder out, String name, String value, boolean first) {
        if (!first) {
            out.append(',');
        }
        out.append('"').append(name).append("\":");
        if (value == null) {
            out.append("null");
        } else {
            out.append('"').append(escape(value)).append('"');
        }
    }

    private static String escape(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n");
    }
}
