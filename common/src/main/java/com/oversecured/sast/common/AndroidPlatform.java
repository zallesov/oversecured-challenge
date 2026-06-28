package com.oversecured.sast.common;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Comparator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Locates the Android SDK {@code android.jar} so the parser's symbol solver can resolve framework
 * calls ({@code WebView.loadUrl}, {@code Intent.getStringExtra}) on a decompiled APK. jadx never
 * emits {@code android.*} framework sources, so without this jar every SDK call is unresolved and
 * the taint signature matcher matches nothing.
 *
 * <p>Resolution is fail-soft: if nothing is found, callers get an empty list and run with no extra
 * classpath (taint will simply not resolve framework signatures). Resolution order:
 * <ol>
 *   <li>{@code SAST_ANDROID_JAR} — an explicit path to an {@code android.jar}.</li>
 *   <li>{@code ANDROID_HOME} then {@code ANDROID_SDK_ROOT} — pick the newest
 *       {@code platforms/android-N/android.jar}.</li>
 *   <li>OS default SDK locations under the user home.</li>
 * </ol>
 */
public final class AndroidPlatform {

    /** Explicit override: a direct path to an {@code android.jar}. */
    public static final String ENV_JAR = "SAST_ANDROID_JAR";

    private static final Pattern PLATFORM = Pattern.compile("android-(\\d+)");

    private AndroidPlatform() {
    }

    /** Resolve using the real process environment and user home; empty if none found. */
    public static List<Path> resolve() {
        return find(System.getenv(), Path.of(System.getProperty("user.home", "")))
                .map(List::of)
                .orElseGet(List::of);
    }

    /**
     * Pure resolver over an injected environment and user home (for tests). Returns the first
     * existing {@code android.jar} per the documented order, or empty.
     */
    public static Optional<Path> find(Map<String, String> env, Path userHome) {
        String explicit = env.get(ENV_JAR);
        if (explicit != null && !explicit.isBlank()) {
            Path jar = Path.of(explicit);
            if (Files.isRegularFile(jar)) {
                return Optional.of(jar.toAbsolutePath().normalize());
            }
        }

        for (String key : List.of("ANDROID_HOME", "ANDROID_SDK_ROOT")) {
            String sdk = env.get(key);
            if (sdk != null && !sdk.isBlank()) {
                Optional<Path> jar = newestPlatformJar(Path.of(sdk));
                if (jar.isPresent()) {
                    return jar;
                }
            }
        }

        if (userHome != null && !userHome.toString().isBlank()) {
            for (Path rel : List.of(Path.of("Library", "Android", "sdk"), Path.of("Android", "Sdk"))) {
                Optional<Path> jar = newestPlatformJar(userHome.resolve(rel));
                if (jar.isPresent()) {
                    return jar;
                }
            }
        }
        return Optional.empty();
    }

    /** Newest {@code <sdk>/platforms/android-N/android.jar} by numeric API level, if any. */
    private static Optional<Path> newestPlatformJar(Path sdkRoot) {
        Path platforms = sdkRoot.resolve("platforms");
        if (!Files.isDirectory(platforms)) {
            return Optional.empty();
        }
        try (Stream<Path> dirs = Files.list(platforms)) {
            return dirs
                    .filter(Files::isDirectory)
                    .filter(p -> PLATFORM.matcher(p.getFileName().toString()).matches())
                    .sorted(Comparator.comparingInt(AndroidPlatform::apiLevel).reversed())
                    .map(p -> p.resolve("android.jar"))
                    .filter(Files::isRegularFile)
                    .map(p -> p.toAbsolutePath().normalize())
                    .findFirst();
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private static int apiLevel(Path platformDir) {
        Matcher m = PLATFORM.matcher(platformDir.getFileName().toString());
        return m.matches() ? Integer.parseInt(m.group(1)) : -1;
    }
}
