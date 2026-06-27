package com.oversecured.sast.taint.cli;

import com.oversecured.sast.taint.TaintAnalyzer;
import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

/** Standalone CLI: {@code taint --ast <ast-index> --facts <facts.json> --rule <rule.yaml> --out <findings.json>}. */
@Command(name = "taint", mixinStandardHelpOptions = true,
        description = "Run rule-driven Android taint analysis")
public final class TaintCommand implements Callable<Integer> {

    @Option(names = "--ast", required = true, description = "ast-index directory")
    Path astIndex;

    @Option(names = "--facts", required = true, description = "manifest facts.json")
    Path factsJson;

    @Option(names = "--rule", required = true, description = "external YAML rule file")
    Path ruleYaml;

    @Option(names = "--out", required = true, description = "output findings.json")
    Path outJson;

    @Override
    public Integer call() {
        new TaintAnalyzer().run(astIndex, factsJson, ruleYaml, outJson);
        System.out.println("taint: wrote findings to " + outJson);
        return 0;
    }

    public static void main(String[] args) {
        System.exit(new CommandLine(new TaintCommand()).execute(args));
    }
}
