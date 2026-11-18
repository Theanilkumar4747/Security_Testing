package com.company.security.utils;

import org.apache.logging.log4j.LogManager;

/** Thin wrapper around Log4j2 so the rest of the code base has one logging entry point. */
public final class Logger {
    private final org.apache.logging.log4j.Logger delegate;

    private Logger(Class<?> c) { this.delegate = LogManager.getLogger(c); }

    public static Logger get(Class<?> c) { return new Logger(c); }

    public void debug(String msg, Object... args) { delegate.debug(msg, args); }
    public void info(String msg, Object... args) { delegate.info(msg, args); }
    public void warn(String msg, Object... args) { delegate.warn(msg, args); }
    public void error(String msg, Throwable t) { delegate.error(msg, t); }
    public void error(String msg, Object... args) { delegate.error(msg, args); }
}
