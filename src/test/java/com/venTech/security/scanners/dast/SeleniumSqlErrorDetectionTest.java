package com.venTech.security.scanners.dast;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import org.junit.jupiter.api.Test;

class SeleniumSqlErrorDetectionTest {
    @Test
    void recognizesCommonDatabaseErrorSignaturesWithoutSendingRequests() {
        List<String> signatures = List.of(
                "SQLSTATE[42000]: syntax error",
                "You have an error in your SQL syntax",
                "Warning: mysql_query() failed",
                "pg_query(): PostgreSQL query failed",
                "unterminated quoted string",
                "ORA-00933: SQL command not properly ended",
                "SQLite error: near input",
                "Microsoft SQL Server: incorrect syntax near input",
                "ODBC SQL Server Driver: unclosed quotation mark",
                "JDBC exception while executing query",
                "Hibernate exception during query");

        for (String signature : signatures) {
            assertThat(SeleniumDashboardScanner.findSqlError("Authentication failed. " + signature))
                    .as("detect database error signature: %s", signature)
                    .isNotNull();
        }
        assertThat(SeleniumDashboardScanner.findSqlError("Invalid username or password")).isNull();
        assertThat(SeleniumDashboardScanner.findSqlError(null)).isNull();
    }
}
