package com.example.app;

public class External {
    public void run(Object client) {
        // Receiver type Object has no user-defined 'doStuff'; the call to an
        // unknown external API cannot be resolved -> resolveSignature empty.
        ((com.unknown.Sdk) client).doStuff("x");
    }
}
