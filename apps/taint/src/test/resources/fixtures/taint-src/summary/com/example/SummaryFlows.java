package com.example;

public class SummaryFlows {
    String id(String in) {
        return in;
    }

    String clean(String in) {
        return "safe";
    }

    public void throughHelper(Intent intent, WebView webView) {
        String url = intent.getStringExtra("url");
        String out = id(url);
        webView.loadUrl(out);
    }

    public void throughCleanHelper(Intent intent, WebView webView) {
        String url = intent.getStringExtra("url");
        String out = clean(url);
        webView.loadUrl(out);
    }

    // Callee whose body sinks its first parameter: makes param 0 sink-reaching.
    void sinkHelper(String url, WebView webView) {
        webView.loadUrl(url);
    }

    // Callee that ignores its tainted parameter and sinks only a clean constant.
    void noSinkHelper(String url, WebView webView) {
        webView.loadUrl("safe");
    }

    // Caller: tainted argument flows into a callee that reaches the sink (inter-procedural).
    public void crossMethodSink(Intent intent, WebView webView) {
        String url = intent.getStringExtra("url");
        sinkHelper(url, webView);
    }

    // Caller: tainted argument flows into a callee that does NOT reach the sink.
    public void crossMethodNoSink(Intent intent, WebView webView) {
        String url = intent.getStringExtra("url");
        noSinkHelper(url, webView);
    }
}
