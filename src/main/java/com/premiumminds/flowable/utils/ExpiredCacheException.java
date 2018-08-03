package com.premiumminds.flowable.utils;

public class ExpiredCacheException extends Exception {

    private static final long serialVersionUID = 1L;

    public ExpiredCacheException() {
    }

    public ExpiredCacheException(String message) {
        super(message);
    }
}
