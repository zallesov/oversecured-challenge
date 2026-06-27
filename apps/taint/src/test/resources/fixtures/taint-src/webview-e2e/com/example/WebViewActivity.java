package com.example;

import android.content.Intent;
import android.webkit.WebView;

public class WebViewActivity {
    public void onCreate(Intent intent, WebView webView) {
        String url = intent.getStringExtra("url");
        webView.loadUrl(url);
    }
}
