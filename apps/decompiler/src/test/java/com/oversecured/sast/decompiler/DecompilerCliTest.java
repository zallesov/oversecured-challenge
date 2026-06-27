package com.oversecured.sast.decompiler;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import java.io.PrintWriter;
import java.io.StringWriter;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;

class DecompilerCliTest {

    @Test
    void missingApkExitsNonZeroWithClearError(@TempDir Path tmp) {
        Path missing = tmp.resolve("nope.apk");
        Path out = tmp.resolve("out");

        StringWriter err = new StringWriter();
        CommandLine cmd = new CommandLine(new DecompilerCli());
        cmd.setErr(new PrintWriter(err));

        int exit = cmd.execute("--apk", missing.toString(), "--out", out.toString());

        assertThat(exit).isNotZero();
        assertThat(err.toString()).contains("decompile failed").contains("not found");
    }

    @Test
    void missingRequiredOptionExitsNonZero(@TempDir Path tmp) {
        CommandLine cmd = new CommandLine(new DecompilerCli());
        cmd.setErr(new PrintWriter(new StringWriter()));

        int exit = cmd.execute("--out", tmp.toString()); // no --apk

        assertThat(exit).isNotZero();
    }
}
