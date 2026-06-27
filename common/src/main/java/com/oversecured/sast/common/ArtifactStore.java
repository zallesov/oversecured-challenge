package com.oversecured.sast.common;

/** Shared artifact contract: every pipeline step reads/writes artifacts by key. */
public interface ArtifactStore {
    void put(String key, byte[] data);

    byte[] get(String key);
}
