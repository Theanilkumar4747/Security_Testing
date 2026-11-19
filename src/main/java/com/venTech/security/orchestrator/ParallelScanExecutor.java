package com.venTech.security.orchestrator;

import com.venTech.security.core.ScanConfig;
import com.venTech.security.core.ScanResult;
import com.venTech.security.core.ScannerInterface;
import com.venTech.security.utils.Logger;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/** Runs scanners concurrently on a bounded pool and never lets one scanner's failure affect the others. */
public class ParallelScanExecutor implements AutoCloseable {
    private static final Logger LOG = Logger.get(ParallelScanExecutor.class);

    public record ScanTask(ScannerInterface scanner, ScanConfig config) {}

    private final ExecutorService pool;

    public ParallelScanExecutor(int threads) {
        this.pool = Executors.newFixedThreadPool(Math.max(1, threads), r -> {
            Thread t = new Thread(r, "scan-worker");
            t.setDaemon(true);
            return t;
        });
    }

    public List<ScanResult> executeAll(List<ScanTask> tasks) {
        List<CompletableFuture<ScanResult>> futures = tasks.stream()
                .map(t -> CompletableFuture.supplyAsync(() -> safeRun(t), pool)).toList();
        return futures.stream().map(CompletableFuture::join).toList();
    }

    private ScanResult safeRun(ScanTask t) {
        try {
            return t.scanner().scan(t.config());
        } catch (RuntimeException e) {
            LOG.error("Unexpected failure in " + t.scanner().name(), e);
            return ScanResult.failed(t.scanner().name(), t.scanner().category(), String.valueOf(e), 0);
        }
    }

    @Override public void close() {
        pool.shutdown();
        try {
            if (!pool.awaitTermination(30, java.util.concurrent.TimeUnit.SECONDS)) {
                pool.shutdownNow();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            pool.shutdownNow();
        }
    }
}
