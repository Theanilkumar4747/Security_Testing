package com.company.security.scanners.api;

import com.company.security.core.BaseScanner;
import com.company.security.core.ScanConfig;
import com.company.security.core.Severity;
import com.company.security.model.Vulnerability;
import com.company.security.utils.EnvConfig;
import com.company.security.utils.FileUtils;
import java.io.StringReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.stream.Stream;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

/**
 * Property-based API fuzzing with Schemathesis (v4 CLI flags). Reads the OpenAPI spec from
 * target.openApiSpec, hits target.url and parses the JUnit report. Pass extra flags with option "extraArgs".
 */
public class SchemathesisRunner extends BaseScanner {
    @Override public String name() { return "schemathesis"; }
    @Override public Category category() { return Category.API; }
    @Override protected String requiredBinary() { return "schemathesis"; }

    @Override
    protected String execute(ScanConfig cfg) throws Exception {
        String spec = cfg.target().openApiSpec();
        if (spec == null || spec.isBlank()) throw new IllegalArgumentException("scan.openapi (OpenAPI spec path/URL) is required");
        Path reportDir = file(cfg, "schemathesis");
        Files.createDirectories(reportDir);
        List<String> cmd = new ArrayList<>(List.of("schemathesis", "run", spec,
                "--url", cfg.target().url(), "--checks", "all",
                "--max-examples", cfg.option("maxExamples", "50"),
                "--report", "junit", "--report-dir", reportDir.toString()));
        String auth = EnvConfig.get("api.auth.header", "");
        if (!auth.isBlank()) { cmd.add("--header"); cmd.add(auth); }
        cfg.listOption("extraArgs", "").forEach(cmd::add);
        run(cfg, cmd, null, 0, 1); // 1 = failures found

        try (Stream<Path> s = Files.list(reportDir)) {
            Path xml = s.filter(p -> p.toString().endsWith(".xml")).max(Comparator.comparingLong(p -> p.toFile().lastModified()))
                    .orElseThrow(() -> new java.io.IOException("No Schemathesis JUnit report produced"));
            return FileUtils.readString(xml);
        }
    }

    @Override
    public List<Vulnerability> parse(String raw) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        Document doc = f.newDocumentBuilder().parse(new InputSource(new StringReader(raw)));
        List<Vulnerability> list = new ArrayList<>();
        NodeList cases = doc.getElementsByTagName("testcase");
        for (int i = 0; i < cases.getLength(); i++) {
            Element tc = (Element) cases.item(i);
            NodeList failures = tc.getElementsByTagName("failure");
            if (failures.getLength() == 0) continue;
            String msg = ((Element) failures.item(0)).getAttribute("message");
            boolean serverError = msg.toLowerCase().contains("server error") || msg.contains("500");
            list.add(Vulnerability.builder()
                    .id("schemathesis-" + Math.abs(tc.getAttribute("name").hashCode()))
                    .title("API contract/robustness failure: " + tc.getAttribute("name"))
                    .description(truncate(msg, 500))
                    .severity(serverError ? Severity.HIGH : Severity.MEDIUM)
                    .scanner(name()).category(category())
                    .location(tc.getAttribute("name"))
                    .remediation("Validate input against the schema and return 4xx for invalid requests")
                    .build());
        }
        return list;
    }
}
