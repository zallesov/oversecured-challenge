package com.oversecured.sast.common;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.Optional;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class AndroidPlatformTest {

    @TempDir
    Path tmp;

    private Path makeJar(Path dir) throws Exception {
        Files.createDirectories(dir);
        Path jar = dir.resolve("android.jar");
        Files.writeString(jar, "stub");
        return jar;
    }

    @Test
    void explicitEnvJarWins() throws Exception {
        Path jar = makeJar(tmp.resolve("custom"));
        Optional<Path> found = AndroidPlatform.find(
                Map.of(AndroidPlatform.ENV_JAR, jar.toString()), tmp.resolve("home"));
        assertThat(found).contains(jar.toAbsolutePath().normalize());
    }

    @Test
    void androidHomePicksNewestApiLevel() throws Exception {
        Path sdk = tmp.resolve("sdk");
        makeJar(sdk.resolve("platforms").resolve("android-30"));
        Path newest = makeJar(sdk.resolve("platforms").resolve("android-34"));
        Optional<Path> found = AndroidPlatform.find(Map.of("ANDROID_HOME", sdk.toString()), tmp);
        assertThat(found).contains(newest.toAbsolutePath().normalize());
    }

    @Test
    void fallsBackToUserHomeSdkLocation() throws Exception {
        Path home = tmp.resolve("home");
        Path newest = makeJar(home.resolve("Library/Android/sdk/platforms/android-35"));
        Optional<Path> found = AndroidPlatform.find(Map.of(), home);
        assertThat(found).contains(newest.toAbsolutePath().normalize());
    }

    @Test
    void emptyWhenNothingResolves() {
        Optional<Path> found = AndroidPlatform.find(Map.of(), tmp.resolve("nope"));
        assertThat(found).isEmpty();
    }

    @Test
    void missingExplicitJarFallsThrough() throws Exception {
        Path sdk = tmp.resolve("sdk");
        Path newest = makeJar(sdk.resolve("platforms").resolve("android-33"));
        Optional<Path> found = AndroidPlatform.find(
                Map.of(AndroidPlatform.ENV_JAR, tmp.resolve("ghost.jar").toString(),
                        "ANDROID_HOME", sdk.toString()),
                tmp);
        assertThat(found).contains(newest.toAbsolutePath().normalize());
    }
}
