package com.example;

public class BasicFlows {
    public void direct(Intent intent, WebView webView) {
        String url = intent.getStringExtra("url");
        webView.loadUrl(url);
    }

    public void killed(Intent intent, WebView webView) {
        String url = intent.getStringExtra("url");
        url = "https://example.com";
        webView.loadUrl(url);
    }

    public void propagated(Intent intent, WebView webView) {
        String url = intent.getStringExtra("url");
        String full = url.concat("/path");
        webView.loadUrl(full);
    }
}
