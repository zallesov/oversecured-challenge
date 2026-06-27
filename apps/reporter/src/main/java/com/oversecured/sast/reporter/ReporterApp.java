package com.oversecured.sast.reporter;

public final class ReporterApp {
    private ReporterApp() {
    }

    public static void main(String[] args) {
        System.out.println(message());
    }

    public static String message() {
        return "Hello World from reporter";
    }
}
