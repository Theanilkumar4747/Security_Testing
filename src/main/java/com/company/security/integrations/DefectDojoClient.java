package com.company.security.integrations;

import com.company.security.utils.EnvConfig;
import com.company.security.utils.HttpUtil;
import java.io.IOException;
import java.nio.file.Path;
import java.time.LocalDate;
import java.util.LinkedHashMap;
import java.util.Map;

/** Imports the SARIF report into DefectDojo (auto-creating product/engagement). Needs defectdojo.url and defectdojo.token. */
public class DefectDojoClient {
    private final String baseUrl;
    private final String token;

    private DefectDojoClient(String baseUrl, String token) { this.baseUrl = baseUrl.replaceAll("/+$", ""); this.token = token; }

    public static DefectDojoClient fromEnv() {
        return new DefectDojoClient(EnvConfig.require("defectdojo.url"), EnvConfig.require("defectdojo.token"));
    }

    public void importScan(Path sarif, String productName) throws IOException, InterruptedException {
        Map<String, String> fields = new LinkedHashMap<>();
        fields.put("scan_type", "SARIF");
        fields.put("product_name", productName);
        fields.put("product_type_name", EnvConfig.get("defectdojo.product.type", "Research and Development"));
        fields.put("engagement_name", EnvConfig.get("defectdojo.engagement", "CI " + LocalDate.now()));
        fields.put("auto_create_context", "true");
        fields.put("close_old_findings", "false");
        HttpUtil.Response r = HttpUtil.postMultipart(baseUrl + "/api/v2/import-scan/",
                Map.of("Authorization", "Token " + token), fields, "file", sarif, "application/json");
        if (r.status() >= 300) throw new IOException("DefectDojo returned HTTP " + r.status() + ": " + r.body());
    }
}
