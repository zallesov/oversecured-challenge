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
}
