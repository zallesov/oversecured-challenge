package com.oversecured.sast.common;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Filesystem-backed {@link ArtifactStore}; keys are relative paths under {@code root}. */
public final class LocalFsStore implements ArtifactStore {

    private final Path root;

    public LocalFsStore(Path root) {
        this.root = root;
    }

    @Override
    public void put(String key, byte[] data) {
        try {
            Path target = root.resolve(key);
            Path parent = target.getParent();
            Files.createDirectories(parent == null ? root : parent);
            Files.write(target, data);
        } catch (IOException e) {
            throw new UncheckedIOException("failed to write artifact: " + key, e);
        }
    }

    @Override
    public byte[] get(String key) {
        try {
            return Files.readAllBytes(root.resolve(key));
        } catch (IOException e) {
            throw new UncheckedIOException("failed to read artifact: " + key, e);
        }
    }
}
