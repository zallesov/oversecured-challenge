package com.example;

import android.content.Intent;
import android.webkit.URLUtil;
import android.webkit.WebView;

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

    public void sanitized(Intent intent, WebView webView) {
        String url = intent.getStringExtra("url");
        if (URLUtil.isHttpsUrl(url)) {
            webView.loadUrl(url);
        }
    }

    public void incompleteSanitized(Intent intent, WebView webView) {
        String url = intent.getStringExtra("url");
        if (url.endsWith("example.com")) {
            webView.loadUrl(url);
        }
    }
}
