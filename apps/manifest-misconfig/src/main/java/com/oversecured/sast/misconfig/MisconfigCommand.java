package com.oversecured.sast.misconfig;

import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(
        name = "mscan",
        mixinStandardHelpOptions = true,
        description = "Analyze Android manifest facts for rule-driven misconfigurations.")
public class MisconfigCommand implements Callable<Integer> {

    @Option(names = "--facts", required = true, description = "Path to facts.json")
    Path factsPath;

    @Option(names = "--rule", required = true, description = "Path to misconfig.yaml")
    Path rulePath;

    @Option(names = "--out", required = true, description = "Path to findings.json")
    Path outPath;

    @Override
    public Integer call() {
        try {
            new MisconfigApp().analyze(factsPath, rulePath, outPath);
            return 0;
        } catch (Exception e) {
            System.err.println("mscan failed: " + e.getMessage());
            return 1;
        }
    }
}
