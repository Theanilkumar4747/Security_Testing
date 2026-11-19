package com.venTech.security.orchestrator;

import com.venTech.security.utils.Logger;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/** Recurring scans (nightly, hourly...). A failed run never cancels the schedule. */
public class ScanScheduler implements AutoCloseable {
    private static final Logger LOG = Logger.get(ScanScheduler.class);
    private final ScheduledExecutorService ses = Executors.newSingleThreadScheduledExecutor();

    public void scheduleEvery(Duration interval, Runnable job) {
        ses.scheduleWithFixedDelay(wrap(job), 0, interval.toSeconds(), TimeUnit.SECONDS);
        LOG.info("Scan scheduled every {}", interval);
    }

    public void scheduleDaily(LocalTime at, Runnable job) {
        LocalDateTime now = LocalDateTime.now();
        LocalDateTime next = now.toLocalDate().atTime(at);
        if (!next.isAfter(now)) next = next.plusDays(1);
        long delay = Duration.between(now, next).toSeconds();
        ses.scheduleAtFixedRate(wrap(job), delay, TimeUnit.DAYS.toSeconds(1), TimeUnit.SECONDS);
        LOG.info("Scan scheduled daily at {} (first run in {} s)", at, delay);
    }

    private Runnable wrap(Runnable job) {
        return () -> {
            try { job.run(); } catch (Throwable t) { LOG.error("Scheduled scan failed", t); }
        };
    }

    @Override public void close() { ses.shutdownNow(); }
}
