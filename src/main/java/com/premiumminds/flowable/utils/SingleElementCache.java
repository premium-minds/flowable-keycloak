package com.premiumminds.flowable.utils;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import org.flowable.ui.common.service.exception.NotFoundException;

public class SingleElementCache<K, V> {

    private static final long CACHE_DURATION_MINUTES = 10;

    private Map<K, V> cacheMap;

    private Instant expiresAt;

    public SingleElementCache() {
        cacheMap = new HashMap<>();
        expiresAt = Instant.now().plus(CACHE_DURATION_MINUTES, ChronoUnit.MINUTES);
    }

    protected boolean isCacheExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    protected boolean isCacheEmpty() {
        return cacheMap.isEmpty();
    }

    public Collection<V> getAll() throws ExpiredCacheException, EmptyCacheException {
        if (!isCacheEmpty()) {
            if (!isCacheExpired()) {
                return cacheMap.values();
            } else {
                cacheMap.clear();
                throw new ExpiredCacheException();
            }
        } else {
            throw new EmptyCacheException();
        }
    }

    public void addElement(K key, V value) {
        cacheMap.put(key, value);
    }

    public void updateExpirationTime() {
        expiresAt = Instant.now().plus(CACHE_DURATION_MINUTES, ChronoUnit.MINUTES);
    }

    public V getElement(K key)
            throws ExpiredCacheException, EmptyCacheException, NotFoundException {
        if (!isCacheEmpty()) {
            if (!isCacheExpired()) {
                if (cacheMap.containsKey(key)) {
                    return cacheMap.get(key);
                } else {
                    throw new NotFoundException();
                }
            } else {
                cacheMap.clear();
                throw new ExpiredCacheException();
            }
        } else {
            throw new EmptyCacheException();
        }
    }

    public boolean hasElement(K key) {
        return cacheMap.containsKey(key);
    }

}
