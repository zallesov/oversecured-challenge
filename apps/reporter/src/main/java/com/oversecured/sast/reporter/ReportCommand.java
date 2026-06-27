package com.oversecured.sast.reporter;

import com.oversecured.sast.common.Finding;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(
        name = "report",
        mixinStandardHelpOptions = true,
        description = "Merge analyzer findings.json files into HTML + SARIF reports.")
public final class ReportCommand implements Callable<Integer> {

    @Option(
            names = "--findings",
            arity = "1..*",
            description = "Findings JSON files to merge.")
    List<Path> findings = new ArrayList<>();

    @Option(names = "--out-html", required = true, description = "HTML report output path.")
    Path outHtml;

    @Option(names = "--out-sarif", required = true, description = "SARIF v2.1.0 output path.")
    Path outSarif;

    @Override
    public Integer call() throws Exception {
        List<Finding> merged = new FindingsMerger().merge(findings);
        writeFile(outHtml, new HtmlReportRenderer().render(merged));
        writeFile(outSarif, new SarifReportWriter().toSarifJson(merged));
        return 0;
    }

    private static void writeFile(Path path, String content) throws Exception {
        Path parent = path.getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(path, content.getBytes(StandardCharsets.UTF_8));
    }

    public static void main(String[] args) {
        System.exit(new CommandLine(new ReportCommand()).execute(args));
    }
}
