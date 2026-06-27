package com.example;

public class DeeplinkActivity {
    public void open(Intent inbound) {
        String url = inbound.getStringExtra("url");
        Intent next = new Intent(this, WebViewActivity.class);
        next.putExtra("url", url);
        startActivity(next);
    }

    public void startActivity(Intent intent) {
    }
}
