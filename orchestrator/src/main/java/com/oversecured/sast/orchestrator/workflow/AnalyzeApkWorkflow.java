package com.oversecured.sast.orchestrator.workflow;

import com.oversecured.sast.orchestrator.AnalysisResult;
import com.oversecured.sast.orchestrator.AnalyzeApkRequest;
import io.temporal.workflow.WorkflowInterface;
import io.temporal.workflow.WorkflowMethod;

@WorkflowInterface
public interface AnalyzeApkWorkflow {

    @WorkflowMethod
    AnalysisResult analyze(AnalyzeApkRequest request);
}
