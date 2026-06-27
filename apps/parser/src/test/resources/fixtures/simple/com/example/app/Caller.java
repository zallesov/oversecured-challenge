package com.example.app;

import com.example.web.WebView;

public class Caller {
    public void open(String url) {
        WebView webView = new WebView();
        webView.loadUrl(url);
    }
}
