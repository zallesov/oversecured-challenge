package com.oversecured.sast.manifestfacts;

import com.oversecured.sast.common.FailureKind;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;
import picocli.CommandLine.Spec;
import picocli.CommandLine.Model.CommandSpec;

import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(
        name = "mfacts",
        mixinStandardHelpOptions = true,
        description = "Extract shared manifest facts from AndroidManifest.xml")
public final class ManifestFactsCommand implements Callable<Integer> {

    private static final Logger log = LoggerFactory.getLogger(ManifestFactsCommand.class);

    /** Function emoji for this outermost boundary (logging conventions §5). */
    private static final String FN = "🧭"; // 🧭

    @Option(names = "--manifest", required = true, description = "Path to AndroidManifest.xml")
    Path manifest;

    @Option(names = "--out", required = true, description = "Path to output facts.json")
    Path out;

    @Spec
    CommandSpec spec;

    private final ManifestFactsApp app = new ManifestFactsApp();

    @Override
    public Integer call() {
        log.info("{} ▶️ mfacts --manifest {} --out {}", FN, manifest, out); // ▶️
        try {
            app.extract(manifest, out);
            log.info("{} ✅ extracted manifest facts {} -> {}", FN, manifest, out); // ✅
            // One human summary line on stdout (logging conventions §2.1); not a step contract.
            spec.commandLine().getOut().println("extracted manifest facts " + manifest + " -> " + out);
            return 0;
        } catch (ManifestFactsException e) {
            // Outermost boundary: log the failure exactly once, then map FailureKind to exit code.
            log.error("{} ❌ manifest-facts failed: {}", FN, e.getMessage()); // ❌
            spec.commandLine().getErr().println("manifest-facts failed: " + e.getMessage());
            return e.kind() == FailureKind.PERMANENT ? 2 : 1;
        }
    }

    public static void main(String[] args) {
        System.exit(new CommandLine(new ManifestFactsCommand()).execute(args));
    }
}
