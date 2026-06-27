package com.oversecured.sast.common;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SignatureParserTest {

    @Test
    void parsesSingleParamSignature() {
        MethodSignature s = SignatureParser.parse(
                "<android.webkit.WebView: void loadUrl(java.lang.String)>");
        assertThat(s.declaringClass()).isEqualTo("android.webkit.WebView");
        assertThat(s.returnType()).isEqualTo("void");
        assertThat(s.name()).isEqualTo("loadUrl");
        assertThat(s.paramTypes()).containsExactly("java.lang.String");
    }

    @Test
    void parsesMultiParamSignature() {
        MethodSignature s = SignatureParser.parse(
                "<java.io.File: void <init>(java.io.File,java.lang.String)>");
        assertThat(s.declaringClass()).isEqualTo("java.io.File");
        assertThat(s.returnType()).isEqualTo("void");
        assertThat(s.name()).isEqualTo("<init>");
        assertThat(s.paramTypes()).containsExactly("java.io.File", "java.lang.String");
    }

    @Test
    void parsesZeroParamSignature() {
        MethodSignature s = SignatureParser.parse(
                "<android.content.Intent: android.net.Uri getData()>");
        assertThat(s.paramTypes()).isEmpty();
        assertThat(s.name()).isEqualTo("getData");
        assertThat(s.returnType()).isEqualTo("android.net.Uri");
    }

    @Test
    void preservesInnerClassDollarSign() {
        MethodSignature s = SignatureParser.parse(
                "<com.example.Outer$Inner: int compute(int)>");
        assertThat(s.declaringClass()).isEqualTo("com.example.Outer$Inner");
        assertThat(s.name()).isEqualTo("compute");
    }

    @Test
    void rejectsMissingAngleBrackets() {
        assertThatThrownBy(() -> SignatureParser.parse("android.webkit.WebView: void loadUrl()"))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void rejectsMissingColon() {
        assertThatThrownBy(() -> SignatureParser.parse("<android.webkit.WebView void loadUrl()>"))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
