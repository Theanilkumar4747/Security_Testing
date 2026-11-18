package com.company.security.reporting;

import com.company.security.gate.QualityGate;
import com.company.security.model.ScanReport;
import com.company.security.utils.FileUtils;
import com.company.security.utils.Logger;
import java.io.IOException;
import java.nio.file.Path;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

/** Writes the requested report formats (html, json, sarif) and returns format -> file. */
public class ReportGenerator {
    private static final Logger LOG = Logger.get(ReportGenerator.class);

    public Map<String, Path> generate(ScanReport report, Path outDir, Collection<String> formats) throws IOException {
        return generate(report, outDir, formats, null);
    }

    public Map<String, Path> generate(ScanReport report, Path outDir, Collection<String> formats,
                                      QualityGate.GateResult gate) throws IOException {
        Map<String, Path> written = new LinkedHashMap<>();
        for (String raw : formats) {
            String f = raw == null ? "" : raw.trim().toLowerCase();
            if (f.isBlank() || written.containsKey(f)) continue;
            try {
                switch (f) {
                    case "html" -> write(written, f, outDir.resolve("security-report.html"), new HtmlReportBuilder().build(report, gate));
                    case "json" -> write(written, f, outDir.resolve("security-report.json"), new JsonReportBuilder().build(report));
                    case "sarif" -> write(written, f, outDir.resolve("security-report.sarif"), new SarifReportBuilder().build(report));
                    default -> throw new IllegalArgumentException("Unknown report format: " + f);
                }
            } catch (IOException | RuntimeException e) {
                throw e;
            } catch (Exception e) {
                throw new IOException("Failed to build " + f + " report", e);
            }
        }
        return written;
    }

    private void write(Map<String, Path> map, String format, Path path, String content) throws IOException {
        FileUtils.writeString(path, content);
        map.put(format, path);
        LOG.info("Generated {} report: {}", format.toUpperCase(), path.toAbsolutePath());
    }
}
