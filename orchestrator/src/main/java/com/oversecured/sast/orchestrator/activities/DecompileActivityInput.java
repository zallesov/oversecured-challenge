package com.oversecured.sast.orchestrator.activities;

public record DecompileActivityInput(String apkPath, String sourcesDirKey, String manifestKey) {
}
