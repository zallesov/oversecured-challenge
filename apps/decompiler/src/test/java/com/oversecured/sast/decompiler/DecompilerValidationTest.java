package com.oversecured.sast.decompiler;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DecompilerValidationTest {

    private final Decompiler decompiler = new Decompiler();

    @Test
    void rejectsMissingApk(@TempDir Path tmp) {
        Path missing = tmp.resolve("does-not-exist.apk");

        assertThatThrownBy(() -> decompiler.validate(missing))
                .isInstanceOf(DecompilerException.class)
                .hasMessageContaining("not found");
    }

    @Test
    void rejectsEmptyApk(@TempDir Path tmp) throws IOException {
        Path empty = Files.createFile(tmp.resolve("empty.apk"));

        assertThatThrownBy(() -> decompiler.validate(empty))
                .isInstanceOf(DecompilerException.class)
                .hasMessageContaining("empty");
    }

    @Test
    void rejectsDirectoryAsApk(@TempDir Path tmp) throws IOException {
        Path dir = Files.createDirectory(tmp.resolve("dir.apk"));

        assertThatThrownBy(() -> decompiler.validate(dir))
                .isInstanceOf(DecompilerException.class)
                .hasMessageContaining("not a regular file");
    }

    @Test
    void acceptsNonEmptyRegularFile(@TempDir Path tmp) throws IOException {
        Path ok = Files.write(tmp.resolve("ok.apk"), new byte[]{1, 2, 3});

        // Should not throw.
        decompiler.validate(ok);
        assertThat(Files.exists(ok)).isTrue();
    }
}
