package com.oversecured.sast.decompiler;

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

    @Option(names = "--apk", required = true, description = "Path to the input APK.")
    Path apk;

    @Option(names = "--out", required = true, description = "Output directory for sources + manifest.")
    Path out;

    @Spec
    CommandSpec spec;

    private final Decompiler decompiler = new Decompiler();

    @Override
    public Integer call() {
        try {
            DecompileResult result = decompiler.decompile(apk, out);
            spec.commandLine().getOut().println("decompiled " + apk + " -> " + result.sourcesDir());
            return 0;
        } catch (DecompilerException e) {
            spec.commandLine().getErr().println("decompile failed: " + e.getMessage());
            return 1;
        }
    }

    public static void main(String[] args) {
        System.exit(new CommandLine(new DecompilerCli()).execute(args));
    }
}
