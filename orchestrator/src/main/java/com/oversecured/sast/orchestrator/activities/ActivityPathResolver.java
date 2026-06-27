package com.oversecured.sast.orchestrator.activities;

import java.nio.file.Path;

public final class ActivityPathResolver {

    private final Path artifactRoot;

    public ActivityPathResolver(Path artifactRoot) {
        this.artifactRoot = artifactRoot.toAbsolutePath().normalize();
    }

    public Path resolveArtifactKey(String key) {
        if (key == null || key.isBlank()) {
            throw new IllegalArgumentException("artifact key must not be blank");
        }
        Path keyPath = Path.of(key);
        if (keyPath.isAbsolute()) {
            throw new IllegalArgumentException("artifact key must be relative: " + key);
        }
        for (Path part : keyPath) {
            if ("..".equals(part.toString())) {
                throw new IllegalArgumentException("artifact key must not contain parent traversal: " + key);
            }
        }
        Path resolved = artifactRoot.resolve(keyPath).toAbsolutePath().normalize();
        if (!resolved.startsWith(artifactRoot)) {
            throw new IllegalArgumentException("artifact key escapes artifact root: " + key);
        }
        return resolved;
    }

    public Path resolveInputPath(String path) {
        if (path == null || path.isBlank()) {
            throw new IllegalArgumentException("input path must not be blank");
        }
        return Path.of(path).toAbsolutePath().normalize();
    }
}
