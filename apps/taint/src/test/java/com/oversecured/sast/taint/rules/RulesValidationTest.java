package com.oversecured.sast.taint.rules;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.oversecured.sast.misconfig.model.MisconfigCheck;
import com.oversecured.sast.misconfig.model.MisconfigRuleFile;
import com.oversecured.sast.taint.model.Rule;
import com.oversecured.sast.taint.model.RuleFile;
import com.oversecured.sast.taint.model.SanitizerSpec;
import com.oversecured.sast.taint.model.SinkSpec;
import com.oversecured.sast.taint.model.SourceSpec;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RulesValidationTest {

    private static final ObjectMapper YAML = new ObjectMapper(new YAMLFactory())
            .setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .configure(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS, true);

    /** Walk up from the test working dir until we find the repo's rules/ dir. */
    static Path rulesDir() {
        Path dir = Path.of("").toAbsolutePath();
        while (dir != null) {
            Path candidate = dir.resolve("rules");
            if (Files.isRegularFile(candidate.resolve("webview.yaml"))) {
                return candidate;
            }
            dir = dir.getParent();
        }
        throw new IllegalStateException("could not locate rules/ directory from " + Path.of("").toAbsolutePath());
    }

    static RuleFile loadRuleFile(String name) throws IOException {
        return YAML.readValue(rulesDir().resolve(name).toFile(), RuleFile.class);
    }

    static MisconfigRuleFile loadMisconfig() throws IOException {
        return YAML.readValue(rulesDir().resolve("misconfig.yaml").toFile(), MisconfigRuleFile.class);
    }

    @Test
    void webviewRuleHasLoadUrlSinkAndIntentSources() throws IOException {
        RuleFile rf = loadRuleFile("webview.yaml");
        assertEquals(1, rf.getRules().size());
        Rule rule = rf.getRules().get(0);
        assertEquals("ANDROID_WEBVIEW_INTENT_LOADURL", rule.getId());

        SinkSpec loadUrl = rule.getSinks().stream()
                .filter(s -> s.getSignature().equals("android.webkit.WebView: void loadUrl(java.lang.String)"))
                .findFirst().orElseThrow();
        assertEquals(java.util.List.of(0), loadUrl.getTaintedArgs());

        long intentSources = rule.getSources().stream()
                .map(SourceSpec::getSignature)
                .filter(sig -> sig.startsWith("android.content.Intent:"))
                .count();
        assertTrue(intentSources >= 2, "expected >=2 Intent sources, got " + intentSources);
    }

    @Test
    void pathTraversalRuleHasTwoFileSinksWithCorrectTaintedArgs() throws IOException {
        RuleFile rf = loadRuleFile("pathtraversal.yaml");
        Rule rule = rf.getRules().get(0);
        assertEquals("ANDROID_PATH_TRAVERSAL_PROVIDER", rule.getId());

        java.util.Map<String, java.util.List<Integer>> bySig = new java.util.HashMap<>();
        for (SinkSpec s : rule.getSinks()) {
            bySig.put(s.getSignature(), s.getTaintedArgs());
        }
        assertEquals(2, bySig.size());
        assertEquals(java.util.List.of(1),
                bySig.get("java.io.File: void <init>(java.io.File,java.lang.String)"));
        assertEquals(java.util.List.of(0),
                bySig.get("android.os.ParcelFileDescriptor: android.os.ParcelFileDescriptor open(java.io.File,int)"));
    }

    @Test
    void sqliteRuleHasRawQueryAndExecSqlSinks() throws IOException {
        RuleFile rf = loadRuleFile("sqlite.yaml");
        Rule rule = rf.getRules().get(0);
        assertEquals("ANDROID_SQLITE_UNTRUSTED_QUERY", rule.getId());

        java.util.Map<String, java.util.List<Integer>> bySig = new java.util.HashMap<>();
        for (SinkSpec s : rule.getSinks()) {
            bySig.put(s.getSignature(), s.getTaintedArgs());
        }
        assertEquals(java.util.List.of(0),
                bySig.get("android.database.sqlite.SQLiteDatabase: android.database.Cursor rawQuery(java.lang.String,java.lang.String[])"));
        assertEquals(java.util.List.of(0),
                bySig.get("android.database.sqlite.SQLiteDatabase: void execSQL(java.lang.String)"));
    }

    @Test
    void webviewJsBridgeRuleHasAddJavascriptInterfaceSink() throws IOException {
        RuleFile rf = loadRuleFile("webview-jsbridge.yaml");
        Rule rule = rf.getRules().get(0);
        assertEquals("ANDROID_WEBVIEW_JS_BRIDGE_EXPORTED", rule.getId());

        SinkSpec bridge = rule.getSinks().stream()
                .filter(s -> s.getSignature().equals(
                        "android.webkit.WebView: void addJavascriptInterface(java.lang.Object,java.lang.String)"))
                .findFirst().orElseThrow();
        assertEquals(java.util.List.of(1), bridge.getTaintedArgs());
        assertTrue(rule.getManifestConditions().isReachableFromExported());
    }

    @Test
    void misconfigFileHasTheFourChecks() throws IOException {
        MisconfigRuleFile mf = loadMisconfig();
        java.util.Set<String> ids = new java.util.HashSet<>();
        for (MisconfigCheck c : mf.getChecks()) {
            ids.add(c.getId());
        }
        assertEquals(java.util.Set.of(
                "exported_without_permission",
                "exported_provider",
                "provider_grant_uri_permissions",
                "weak_host_validation"), ids);
    }

    @Test
    void endToEnd_allThreeFilesLoad_andEverySignatureParses() throws IOException {
        // 1. Taint rule files load into RuleFile.
        RuleFile webview = loadRuleFile("webview.yaml");
        RuleFile pathtrav = loadRuleFile("pathtraversal.yaml");
        RuleFile sqlite = loadRuleFile("sqlite.yaml");
        RuleFile jsBridge = loadRuleFile("webview-jsbridge.yaml");
        RuleFile intentRedirect = loadRuleFile("intent-redirect.yaml");
        RuleFile fileTheft = loadRuleFile("file-theft.yaml");
        RuleFile loginUrl = loadRuleFile("login-url-injection.yaml");
        RuleFile credLog = loadRuleFile("credential-log-leak.yaml");

        // webview.yaml: loadUrl sink arg[0] + >=2 Intent sources
        SinkSpec loadUrl = webview.getRules().get(0).getSinks().stream()
                .filter(s -> s.getSignature().equals("android.webkit.WebView: void loadUrl(java.lang.String)"))
                .findFirst().orElseThrow();
        assertEquals(java.util.List.of(0), loadUrl.getTaintedArgs());
        assertTrue(webview.getRules().get(0).getSources().stream()
                .filter(s -> s.getSignature().startsWith("android.content.Intent:"))
                .count() >= 2);

        // pathtraversal.yaml: the two file sinks with correct tainted args
        java.util.Map<String, java.util.List<Integer>> ptSinks = new java.util.HashMap<>();
        for (SinkSpec s : pathtrav.getRules().get(0).getSinks()) {
            ptSinks.put(s.getSignature(), s.getTaintedArgs());
        }
        assertEquals(java.util.List.of(1),
                ptSinks.get("java.io.File: void <init>(java.io.File,java.lang.String)"));
        assertEquals(java.util.List.of(0),
                ptSinks.get("android.os.ParcelFileDescriptor: android.os.ParcelFileDescriptor open(java.io.File,int)"));

        // 2. misconfig.yaml loads into MisconfigRuleFile with exactly the four checks
        assertEquals(4, loadMisconfig().getChecks().size());

        // 3. Every source/sink/sanitizer signature in all taint files parses via the rule loader adapter.
        for (RuleFile rf : java.util.List.of(webview, pathtrav, sqlite, jsBridge,
                intentRedirect, fileTheft, loginUrl, credLog)) {
            for (Rule rule : rf.getRules()) {
                for (SourceSpec src : rule.getSources()) {
                    assertNotNull(RuleSignatures.parseMethod(src.getSignature()),
                            "source did not parse: " + src.getSignature());
                }
                for (SinkSpec sink : rule.getSinks()) {
                    assertNotNull(RuleSignatures.parseMethod(sink.getSignature()),
                            "sink did not parse: " + sink.getSignature());
                }
                for (SanitizerSpec san : rule.getSanitizers()) {
                    assertNotNull(RuleSignatures.parseMethod(san.getSignature()),
                            "sanitizer did not parse: " + san.getSignature());
                }
                if (rule.getPropagators() != null) {
                    for (String prop : rule.getPropagators()) {
                        assertNotNull(RuleSignatures.parseMethod(prop),
                                "propagator did not parse: " + prop);
                    }
                }
            }
        }
    }
}
