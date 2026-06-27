package com.oversecured.sast.manifestfacts;

import org.w3c.dom.Element;

final class XmlNames {
    static final String ANDROID_NS = "http://schemas.android.com/apk/res/android";

    private XmlNames() {
    }

    static String androidAttr(Element element, String localName) {
        String namespaced = element.getAttributeNS(ANDROID_NS, localName);
        if (namespaced != null && !namespaced.isBlank()) {
            return namespaced;
        }
        String prefixed = element.getAttribute("android:" + localName);
        return prefixed == null || prefixed.isBlank() ? null : prefixed;
    }
}
