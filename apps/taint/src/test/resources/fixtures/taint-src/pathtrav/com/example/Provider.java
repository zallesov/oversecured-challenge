package com.example;

import android.net.Uri;
import android.os.ParcelFileDescriptor;
import java.io.File;

public class Provider {
    public ParcelFileDescriptor openFile(Uri uri) {
        File file = new File(new File("/tmp"), uri.getLastPathSegment());
        return ParcelFileDescriptor.open(file, 0);
    }
}
