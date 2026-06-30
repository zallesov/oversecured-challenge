package com.oversecured.sast.orchestrator.cli;

import com.oversecured.sast.orchestrator.TaskQueues;
import com.oversecured.sast.orchestrator.activities.PipelineActivitiesImpl;
import com.oversecured.sast.orchestrator.workflow.AnalyzeApkWorkflowImpl;
import com.oversecured.sast.orchestrator.workflow.CallbackContextPropagator;
import com.oversecured.sast.orchestrator.workflow.StatusEmitInterceptor;
import io.temporal.client.WorkflowClient;
import io.temporal.client.WorkflowClientOptions;
import io.temporal.serviceclient.WorkflowServiceStubs;
import io.temporal.serviceclient.WorkflowServiceStubsOptions;
import io.temporal.worker.Worker;
import io.temporal.worker.WorkerFactory;
import io.temporal.worker.WorkerFactoryOptions;
import io.temporal.worker.WorkerOptions;
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
        WorkflowClient client = WorkflowClient.newInstance(service,
                WorkflowClientOptions.newBuilder()
                        .setContextPropagators(java.util.List.of(new CallbackContextPropagator()))
                        .build());
        WorkerFactoryOptions factoryOptions = WorkerFactoryOptions.newBuilder()
                .setWorkerInterceptors(new StatusEmitInterceptor())
                .build();
        WorkerFactory factory = WorkerFactory.newInstance(client, factoryOptions);
        // Cap concurrent activities: each taint/parse activity re-parses the decompiled tree with an
        // android.jar solver (memory-heavy). Bounding peak parallelism keeps the worker off the OOM
        // line; tune with MAX_CONCURRENT_ACTIVITIES.
        int maxActivities = intEnv("MAX_CONCURRENT_ACTIVITIES", 4);
        Worker worker = factory.newWorker(TaskQueues.DEFAULT, WorkerOptions.newBuilder()
                .setMaxConcurrentActivityExecutionSize(maxActivities)
                .build());

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

    private static int intEnv(String name, int fallback) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            return fallback;
        }
        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return fallback;
        }
    }
}
