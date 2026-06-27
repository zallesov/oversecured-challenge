package com.oversecured.sast.orchestrator;

public record AnalyzeApkRequest(String apkPath, AnalysisPlan plan) {
}
