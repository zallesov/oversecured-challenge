package com.oversecured.sast.manifestfacts;

import com.oversecured.sast.common.FailureKind;
import com.oversecured.sast.common.Json;
import com.oversecured.sast.common.ManifestFacts;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Library API: extract shared manifest facts and write the {@code facts.json} artifact. */
public final class ManifestFactsApp {

    private static final Logger log = LoggerFactory.getLogger(ManifestFactsApp.class);

    /** Function emoji for this boundary (logging conventions §5). */
    private static final String FN = "📜"; // 📜

    private final AndroidManifestFactsExtractor extractor;

    public ManifestFactsApp() {
        this(new AndroidManifestFactsExtractor());
    }

    ManifestFactsApp(AndroidManifestFactsExtractor extractor) {
        this.extractor = extractor;
    }

    /**
     * Extracts facts from {@code manifest} and writes them as deterministic {@code facts.json} to {@code out}.
     *
     * <p>This is the module service boundary: it logs lifecycle and translates raw failures into
     * {@link ManifestFactsException} with an explicit {@link FailureKind} (error-handling conventions §3).
     * A bad/corrupt manifest is PERMANENT; an output filesystem fault is TRANSIENT.
     *
     * @throws ManifestFactsException on unparseable manifest input or output write failure.
     */
    public ManifestFacts extract(Path manifest, Path out) {
        log.info("{} ▶️ extracting facts {} -> {}", FN, manifest, out); // ▶️

        ManifestFacts facts;
        try {
            facts = extractor.extract(manifest);
        } catch (IOException e) {
            // Unparseable/corrupt/missing manifest is bad input -> not retryable.
            throw new ManifestFactsException(FailureKind.PERMANENT,
                    "could not parse AndroidManifest.xml: " + manifest + " (" + e.getMessage() + ")", e);
        }

        try {
            Path parent = out.toAbsolutePath().getParent();
            if (parent != null) {
                Files.createDirectories(parent);
            }
            Files.write(out, Json.writeBytes(facts));
        } catch (IOException e) {
            // Output filesystem fault is environmental -> retryable.
            throw new ManifestFactsException(FailureKind.TRANSIENT,
                    "could not write facts.json: " + out + " (" + e.getMessage() + ")", e);
        }

        log.info("{} 📁 wrote facts.json ({} components) to {}", FN, facts.components().size(), out); // 📁
        return facts;
    }
}
