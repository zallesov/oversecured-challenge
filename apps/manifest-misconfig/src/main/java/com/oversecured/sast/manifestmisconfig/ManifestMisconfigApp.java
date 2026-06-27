package com.oversecured.sast.manifestmisconfig;

public final class ManifestMisconfigApp {
    private ManifestMisconfigApp() {
    }

    public static void main(String[] args) {
        System.out.println(message());
    }

    public static String message() {
        return "Hello World from manifest-misconfig";
    }
}
