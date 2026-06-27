package com.oversecured.sast.orchestrator;

import static org.assertj.core.api.Assertions.assertThat;

import com.oversecured.sast.orchestrator.cli.StartAnalysisCommand;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

class StartAnalysisCommandTest {

    @Test
    void commandBuildsRequestAndStartsWorkflow() {
        RecordingStarter starter = new RecordingStarter();
        int exit = new CommandLine(new StartAnalysisCommand(starter)).execute(
                "--apk", "/tmp/ovaa.apk",
                "--run-id", "ovaa-001",
                "--temporal", "127.0.0.1:7233",
                "--rules", "webview,pathtraversal");

        assertThat(exit).isEqualTo(0);
        assertThat(starter.target).isEqualTo("127.0.0.1:7233");
        assertThat(starter.workflowId).isEqualTo("android-sast-ovaa-001");
        assertThat(starter.requests).containsExactly(new AnalyzeApkRequest(
                "/tmp/ovaa.apk",
                AnalysisPlan.forRules("ovaa-001", List.of("webview", "pathtraversal"))));
    }

    @Test
    void commandRejectsUnsafeRunIdBeforeStartingWorkflow() {
        RecordingStarter starter = new RecordingStarter();
        int exit = new CommandLine(new StartAnalysisCommand(starter)).execute(
                "--apk", "/tmp/ovaa.apk",
                "--run-id", "../escape",
                "--rules", "webview");

        assertThat(exit).isNotEqualTo(0);
        assertThat(starter.requests).isEmpty();
    }

    private static final class RecordingStarter implements StartAnalysisCommand.WorkflowStarter {
        private String target;
        private String workflowId;
        private final List<AnalyzeApkRequest> requests = new ArrayList<>();

        @Override
        public AnalysisResult start(String temporalTarget, String workflowId, AnalyzeApkRequest request) {
            this.target = temporalTarget;
            this.workflowId = workflowId;
            this.requests.add(request);
            return new AnalysisResult(request.plan().report().htmlKey(), request.plan().report().sarifKey());
        }
    }
}
