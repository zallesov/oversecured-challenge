package com.oversecured.sast.misconfig;

import picocli.CommandLine;

public final class Main {
    private Main() {
    }

    public static void main(String[] args) {
        int exit = new CommandLine(new MisconfigCommand()).execute(args);
        System.exit(exit);
    }
}
