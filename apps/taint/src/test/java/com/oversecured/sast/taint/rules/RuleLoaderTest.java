package com.oversecured.sast.taint.rules;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import com.oversecured.sast.common.MethodSignature;
import com.oversecured.sast.common.Severity;
import com.oversecured.sast.taint.model.RuleFile;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

class RuleLoaderTest {
    private static Path fixture(String name) {
        return Path.of("src", "test", "resources", "fixtures", "rules", name);
    }

    @Test
    void loadsSnakeCaseYamlAndLowercaseSeverity() {
        RuleFile rf = new RuleLoader().load(fixture("webview-mini.yaml"));
        assertThat(rf.getVersion()).isEqualTo(1);
        assertThat(rf.getRules()).hasSize(1);
        assertThat(rf.getRules().get(0).getSeverity()).isEqualTo(Severity.ERROR);
        assertThat(rf.getRules().get(0).getManifestConditions().isReachableFromExported()).isTrue();
        assertThat(rf.getRules().get(0).getSinks().get(0).getTaintedArgs()).containsExactly(0);
    }

    @Test
    void canonicalizesBareAndBracketedSignaturesThroughCommonParser() {
        MethodSignature bare = RuleSignatures.parseMethod(
                "android.webkit.WebView: void loadUrl(java.lang.String)");
        MethodSignature bracketed = RuleSignatures.parseMethod(
                "<android.webkit.WebView: void loadUrl(java.lang.String)>");

        assertThat(bare).isEqualTo(bracketed);
        assertThat(bare.declaringClass()).isEqualTo("android.webkit.WebView");
        assertThat(bare.name()).isEqualTo("loadUrl");
        assertThat(RuleSignatures.canonical("android.webkit.WebView: void loadUrl(java.lang.String)"))
                .isEqualTo("<android.webkit.WebView: void loadUrl(java.lang.String)>");
    }

    @Test
    void rejectsMalformedRuleSignatures() {
        assertThatThrownBy(() -> RuleSignatures.parseMethod("not a method"))
                .isInstanceOf(IllegalArgumentException.class)
                .hasMessageContaining("malformed signature");
    }
}
