package com.oversecured.sast.benchmark;

public final class BenchmarkApp {
    private BenchmarkApp() {
    }

    public static void main(String[] args) {
        System.out.println(message());
    }

    public static String message() {
        return "Hello World from benchmark";
    }
}
