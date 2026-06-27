package com.oversecured.sast.orchestrator.cli;

import com.oversecured.sast.orchestrator.TaskQueues;
import com.oversecured.sast.orchestrator.activities.PipelineActivitiesImpl;
import com.oversecured.sast.orchestrator.workflow.AnalyzeApkWorkflowImpl;
import io.temporal.client.WorkflowClient;
import io.temporal.serviceclient.WorkflowServiceStubs;
import io.temporal.serviceclient.WorkflowServiceStubsOptions;
import io.temporal.worker.Worker;
import io.temporal.worker.WorkerFactory;
import java.nio.file.Path;

public final class WorkerMain {

    private WorkerMain() {
    }

    public static void main(String[] args) {
        String temporalTarget = env("TEMPORAL_ADDRESS", "127.0.0.1:7233");
        Path artifactRoot = Path.of(env("ARTIFACT_ROOT", "artifacts"));

        WorkflowServiceStubs service = WorkflowServiceStubs.newServiceStubs(
                WorkflowServiceStubsOptions.newBuilder()
                        .setTarget(temporalTarget)
                        .build());
        WorkflowClient client = WorkflowClient.newInstance(service);
        WorkerFactory factory = WorkerFactory.newInstance(client);
        Worker worker = factory.newWorker(TaskQueues.DEFAULT);

        worker.registerWorkflowImplementationTypes(AnalyzeApkWorkflowImpl.class);
        worker.registerActivitiesImplementations(new PipelineActivitiesImpl(artifactRoot));
        factory.start();

        Runtime.getRuntime().addShutdownHook(new Thread(factory::shutdown));
        System.out.println("orchestrator worker started on taskQueue=" + TaskQueues.DEFAULT);
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return value == null || value.isBlank() ? fallback : value;
    }
}
