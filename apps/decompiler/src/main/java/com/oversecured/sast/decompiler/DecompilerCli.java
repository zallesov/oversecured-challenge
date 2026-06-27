package com.oversecured.sast.decompiler;

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
        name = "decompile",
        mixinStandardHelpOptions = true,
        description = "Decompile an Android APK into a .java source tree + decoded AndroidManifest.xml.")
public final class DecompilerCli implements Callable<Integer> {

    private static final Logger log = LoggerFactory.getLogger(DecompilerCli.class);

    /** Function emoji for this outermost boundary (logging conventions §5). */
    private static final String FN = "🚀"; // 🚀

    @Option(names = "--apk", required = true, description = "Path to the input APK.")
    Path apk;

    @Option(names = "--out", required = true, description = "Output directory for sources + manifest.")
    Path out;

    @Spec
    CommandSpec spec;

    private final Decompiler decompiler = new Decompiler();

    @Override
    public Integer call() {
        log.info("{} ▶️ decompile --apk {} --out {}", FN, apk, out); // ▶️
        try {
            DecompileResult result = decompiler.decompile(apk, out);
            log.info("{} ✅ decompiled {} -> {}", FN, apk, result.sourcesDir()); // ✅
            // One human summary line on stdout (logging conventions §2.1); not a step contract.
            spec.commandLine().getOut().println("decompiled " + apk + " -> " + result.sourcesDir());
            return 0;
        } catch (DecompilerException e) {
            // Outermost boundary: log the failure exactly once, then map FailureKind to exit code.
            log.error("{} ❌ decompile failed: {}", FN, e.getMessage()); // ❌
            spec.commandLine().getErr().println("decompile failed: " + e.getMessage());
            return e.kind() == FailureKind.PERMANENT ? 2 : 1;
        }
    }

    public static void main(String[] args) {
        System.exit(new CommandLine(new DecompilerCli()).execute(args));
    }
}
