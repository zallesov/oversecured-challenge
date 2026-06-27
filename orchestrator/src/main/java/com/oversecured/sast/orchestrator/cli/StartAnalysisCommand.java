package com.oversecured.sast.orchestrator.cli;

import com.oversecured.sast.orchestrator.AnalysisPlan;
import com.oversecured.sast.orchestrator.AnalysisResult;
import com.oversecured.sast.orchestrator.AnalyzeApkRequest;
import com.oversecured.sast.orchestrator.RuleCatalog;
import com.oversecured.sast.orchestrator.TaskQueues;
import java.nio.file.Path;
import java.util.List;
import com.oversecured.sast.orchestrator.workflow.AnalyzeApkWorkflow;
import io.temporal.client.WorkflowClient;
import io.temporal.client.WorkflowOptions;
import io.temporal.serviceclient.WorkflowServiceStubs;
import io.temporal.serviceclient.WorkflowServiceStubsOptions;
import java.util.concurrent.Callable;
import picocli.CommandLine;

@CommandLine.Command(name = "start-analysis", mixinStandardHelpOptions = true)
public final class StartAnalysisCommand implements Callable<Integer> {

    @CommandLine.Option(names = "--apk", required = true)
    private String apk;

    @CommandLine.Option(names = "--run-id", required = true)
    private String runId;

    @CommandLine.Option(names = "--temporal", defaultValue = "127.0.0.1:7233")
    private String temporalTarget;

    @CommandLine.Option(names = "--rules", defaultValue = RuleCatalog.ALL,
            description = "Comma-separated taint rule names (file base names), or 'all' (default) "
                    + "to run every rule in --rules-dir.")
    private String rules;

    @CommandLine.Option(names = "--rules-dir", defaultValue = "rules",
            description = "Directory listed to expand --rules=all. Default: rules")
    private String rulesDir;

    private final WorkflowStarter starter;

    public StartAnalysisCommand() {
        this(new TemporalWorkflowStarter());
    }

    public StartAnalysisCommand(WorkflowStarter starter) {
        this.starter = starter;
    }

    @Override
    public Integer call() {
        List<String> ruleNames = new RuleCatalog(Path.of(rulesDir)).resolve(rules);
        System.out.println("rules=" + ruleNames);
        AnalysisPlan plan = AnalysisPlan.forRules(runId, ruleNames);
        String workflowId = "android-sast-" + runId;
        AnalysisResult result = starter.start(temporalTarget, workflowId, new AnalyzeApkRequest(apk, plan));
        System.out.println("html=" + result.htmlReportKey());
        System.out.println("sarif=" + result.sarifReportKey());
        return 0;
    }

    public static void main(String[] args) {
        System.exit(new CommandLine(new StartAnalysisCommand()).execute(args));
    }

    public interface WorkflowStarter {
        AnalysisResult start(String temporalTarget, String workflowId, AnalyzeApkRequest request);
    }

    private static final class TemporalWorkflowStarter implements WorkflowStarter {
        @Override
        public AnalysisResult start(String temporalTarget, String workflowId, AnalyzeApkRequest request) {
            WorkflowServiceStubs service = WorkflowServiceStubs.newServiceStubs(
                    WorkflowServiceStubsOptions.newBuilder()
                            .setTarget(temporalTarget)
                            .build());
            WorkflowClient client = WorkflowClient.newInstance(service);
            AnalyzeApkWorkflow workflow = client.newWorkflowStub(
                    AnalyzeApkWorkflow.class,
                    WorkflowOptions.newBuilder()
                            .setWorkflowId(workflowId)
                            .setTaskQueue(TaskQueues.DEFAULT)
                            .build());
            return workflow.analyze(request);
        }
    }
}
