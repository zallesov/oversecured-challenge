package com.example;

public class WebViewActivity {
    public void onCreate(Intent inbound, WebView webView) {
        String url = inbound.getStringExtra("url");
        webView.loadUrl(url);
    }
}
