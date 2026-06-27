package com.oversecured.sast.parser.cli;

import com.oversecured.sast.common.FailureKind;
import com.oversecured.sast.parser.AstIndex;
import com.oversecured.sast.parser.ParserException;

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
    name = "parse",
    mixinStandardHelpOptions = true,
    description = "Parse a decompiled Java source tree into a reusable ast-index artifact.")
public final class ParseCommand implements Callable<Integer> {

    private static final Logger log = LoggerFactory.getLogger(ParseCommand.class);

    /** Function emoji for this outermost boundary (logging conventions §5). */
    private static final String FN = "🚀"; // 🚀

    @Option(names = "--src", required = true, description = "Decompiled sources/ directory.")
    Path src;

    @Option(names = "--out", required = true, description = "Output ast-index/ directory.")
    Path out;

    @Spec
    CommandSpec spec;

    @Override
    public Integer call() {
        log.info("{} ▶️ parse --src {} --out {}", FN, src, out); // ▶️
        try {
            AstIndex index = AstIndex.build(src);
            index.save(out);
            log.info("{} ✅ parsed {} compilation unit(s) -> {}", FN, index.units().size(), out); // ✅
            // One human summary line on stdout (logging conventions §2.1); not a step contract.
            spec.commandLine().getOut().println("parsed " + index.units().size()
                + " compilation unit(s); ast-index written to " + out.toAbsolutePath());
            return 0;
        } catch (ParserException e) {
            // Outermost boundary: log the failure exactly once, then map FailureKind to exit code.
            log.error("{} ❌ parse failed: {}", FN, e.getMessage()); // ❌
            spec.commandLine().getErr().println("parse failed: " + e.getMessage());
            return e.kind() == FailureKind.PERMANENT ? 2 : 1;
        }
    }

    public static int run(String... args) {
        return new CommandLine(new ParseCommand()).execute(args);
    }

    public static void main(String[] args) {
        System.exit(run(args));
    }
}
