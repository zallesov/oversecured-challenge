package com.oversecured.sast.orchestrator;

public final class OrchestratorApp {
    private OrchestratorApp() {
    }

    public static void main(String[] args) {
        System.out.println(message());
    }

    public static String message() {
        return "Hello World from orchestrator";
    }
}
