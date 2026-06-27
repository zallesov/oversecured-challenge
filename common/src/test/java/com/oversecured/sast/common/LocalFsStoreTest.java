package com.oversecured.sast.common;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.charset.StandardCharsets;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class LocalFsStoreTest {

    @Test
    void putThenGetRoundTrips(@TempDir Path root) {
        ArtifactStore store = new LocalFsStore(root);
        byte[] payload = "hello-artifact".getBytes(StandardCharsets.UTF_8);

        store.put("nested/dir/file.txt", payload);
        byte[] read = store.get("nested/dir/file.txt");

        assertThat(read).isEqualTo(payload);
    }
}
