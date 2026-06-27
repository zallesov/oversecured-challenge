# Manifest Facts (Step 3) Implementation Plan

**Shared conventions:** [Shared Contracts and Naming Conventions](../reference/2026-06-27-shared-contracts-and-conventions.md)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build `apps/manifest-facts`, the standalone step that reads `AndroidManifest.xml` and writes the shared `ManifestFacts` artifact as `facts.json`.

**Architecture:** The module is a small Java 17 application with a pure DOM-based extractor, a library facade, and a thin picocli CLI named `mfacts`. XML parsing stays in the JDK (`DocumentBuilderFactory`) and all output uses `com.oversecured.sast.common.Json` plus the shared `ManifestFacts`, `ComponentFact`, and `IntentFilterFact` records from `common`; this step extracts facts only and never emits analyzer findings.

**Tech Stack:** Java 17; Gradle Groovy DSL; JUnit 5 + AssertJ; Jackson through `common`; picocli from `rootProject.ext.picocliVersion`; standard Java DOM XML parsing.

## Global Constraints

- Module path: `apps/manifest-facts`; Gradle module: `:apps:manifest-facts`.
- Package root: `com.oversecured.sast.manifestfacts`.
- CLI shape: `mfacts --manifest <AndroidManifest.xml> --out <facts.json>`.
- Default pipeline input is `sources/AndroidManifest.xml`; CLI must accept any explicit manifest path.
- Output artifact is `facts.json`, serialized from `com.oversecured.sast.common.ManifestFacts`.
- Consume shared records exactly as defined by `common`: `ManifestFacts(String packageName, List<ComponentFact> components, List<String> permissions)`, `ComponentFact(String name, String type, boolean exported, List<IntentFilterFact> intentFilters, boolean grantUriPermissions, String permission)`, `IntentFilterFact(List<String> actions, List<String> schemes, List<String> hosts)`.
- Do not define duplicate manifest model records in `apps/manifest-facts`.
- Do not produce `Finding`, `FindingsDoc`, SARIF, HTML, or analyzer-specific decisions. This module extracts facts only.
- XML parser must be hardened against XXE and external entity resolution.
- No Android SDK dependency: parse namespaced attributes by URI/local-name and by fallback `android:*` attribute names.
- Exported logic:
  - Android 12/API 31 rule: if a component has an explicit `android:exported`, use it.
  - Pre-31 default rule: if `android:exported` is absent, `activity`, `service`, and `receiver` are exported when they have at least one `intent-filter`; otherwise false.
  - Providers default to false when `android:exported` is absent for this artifact, because the shared schema has no target SDK field and analyzers need a conservative, deterministic boolean.
- Component coverage: `activity`, `activity-alias`, `service`, `receiver`, and `provider`. Store `activity-alias` facts with `type` set to `activity`.
- Provider coverage includes `android:grantUriPermissions` as `ComponentFact.grantUriPermissions()`. Non-provider components set this field to false.
- Intent-filter coverage: actions, categories for exported detection only, data schemes, and data hosts. The shared `IntentFilterFact` schema has no `categories` field, so categories are parsed only to validate filter presence and are not serialized.
- Manifest permissions coverage: collect `<uses-permission android:name="...">`, `<uses-permission-sdk-23 android:name="...">`, and `<permission android:name="...">` names into `ManifestFacts.permissions()`, sorted and de-duplicated.
- Component permission coverage: prefer component-level `android:permission`; for `activity`, `service`, and `receiver`, fall back to the application-level permission attribute when component-level permission is absent. Providers also use component-level `android:readPermission` or `android:writePermission` when `android:permission` is absent, joined as `read=<permission>;write=<permission>` when both exist.
- Deterministic output: components preserve manifest order; lists inside facts are sorted and de-duplicated.
- Gradle dependencies come from root `ext`; no hardcoded duplicate versions.

## File Structure

```
apps/manifest-facts/
|-- build.gradle
`-- src/
    |-- main/java/com/oversecured/sast/manifestfacts/
    |   |-- AndroidManifestFactsExtractor.java   # pure DOM parser: Path -> ManifestFacts
    |   |-- ManifestFactsApp.java                # library API: extract(manifest, out)
    |   |-- ManifestFactsCommand.java            # picocli CLI and main()
    |   `-- XmlNames.java                        # Android namespace attribute helpers
    `-- test/
        |-- java/com/oversecured/sast/manifestfacts/
        |   |-- AndroidManifestFactsExtractorTest.java
        |   |-- ManifestFactsCommandTest.java
        |   `-- ManifestFactsAppTest.java
        `-- resources/manifests/
            |-- exported-explicit.xml
            |-- exported-defaults.xml
            |-- permissions-and-provider.xml
            `-- deeplink-data.xml
```

## Task 1: Gradle application module and shared-contract smoke test

**Files:**
- Modify: `apps/manifest-facts/build.gradle`
- Create: `apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractorTest.java`

**Interfaces:**
- Consumes: root Gradle build and `common` module from `2026-06-27-common.md`.
- Produces: application module wired to `project(':common')`, Jackson via `common`, picocli via root `ext`, and test access to shared manifest records.

- [ ] **Step 1: Write the failing test**

Create `apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractorTest.java`:

```java
package com.oversecured.sast.manifestfacts;

import com.oversecured.sast.common.ComponentFact;
import com.oversecured.sast.common.IntentFilterFact;
import com.oversecured.sast.common.ManifestFacts;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AndroidManifestFactsExtractorTest {

    @Test
    void sharedManifestFactsModelIsReachable() {
        ManifestFacts facts = new ManifestFacts(
                "oversecured.ovaa",
                List.of(new ComponentFact(
                        "oversecured.ovaa.activities.DeeplinkActivity",
                        "activity",
                        true,
                        List.of(new IntentFilterFact(
                                List.of("android.intent.action.VIEW"),
                                List.of("oversecured"),
                                List.of("ovaa"))),
                        false,
                        null)),
                List.of("android.permission.INTERNET"));

        assertThat(facts.packageName()).isEqualTo("oversecured.ovaa");
        assertThat(facts.components()).hasSize(1);
        assertThat(facts.components().get(0).exported()).isTrue();
        assertThat(facts.components().get(0).intentFilters().get(0).schemes())
                .containsExactly("oversecured");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :apps:manifest-facts:test --tests 'com.oversecured.sast.manifestfacts.AndroidManifestFactsExtractorTest.sharedManifestFactsModelIsReachable' --no-daemon`

Expected: FAIL with either `Project ':apps:manifest-facts' not found`, `package com.oversecured.sast.common does not exist`, or missing test dependencies.

- [ ] **Step 3: Write minimal implementation**

Replace `apps/manifest-facts/build.gradle` with:

```groovy
plugins {
    id 'application'
}

dependencies {
    implementation project(':common')
    implementation "info.picocli:picocli:${rootProject.ext.picocliVersion}"
    annotationProcessor "info.picocli:picocli-codegen:${rootProject.ext.picocliVersion}"
}

application {
    mainClass = 'com.oversecured.sast.manifestfacts.ManifestFactsCommand'
    applicationName = 'mfacts'
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :apps:manifest-facts:test --tests 'com.oversecured.sast.manifestfacts.AndroidManifestFactsExtractorTest.sharedManifestFactsModelIsReachable' --no-daemon`

Expected: PASS with 1 test.

- [ ] **Step 5: Commit**

```bash
git add apps/manifest-facts/build.gradle apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractorTest.java
git commit -m "build(manifest-facts): configure application module with common contracts"
```

## Task 2: Secure XML loading and package name extraction

**Files:**
- Create: `apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/XmlNames.java`
- Create: `apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractor.java`
- Modify: `apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractorTest.java`
- Create: `apps/manifest-facts/src/test/resources/manifests/exported-explicit.xml`

**Interfaces:**
- Consumes: `Path`.
- Produces: `AndroidManifestFactsExtractor.extract(Path manifestPath) throws IOException`, returning `ManifestFacts`.

- [ ] **Step 1: Add fixture and failing test**

Create `apps/manifest-facts/src/test/resources/manifests/exported-explicit.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="oversecured.ovaa">
    <application android:permission="oversecured.ovaa.permission.INTERNAL">
        <activity
            android:name=".activities.DeeplinkActivity"
            android:exported="true" />
        <service
            android:name="oversecured.ovaa.SyncService"
            android:exported="false" />
    </application>
</manifest>
```

Append to `AndroidManifestFactsExtractorTest.java`:

```java
    private java.nio.file.Path fixture(String name) throws Exception {
        return java.nio.file.Paths.get(getClass().getResource("/manifests/" + name).toURI());
    }

    @Test
    void extract_readsPackageName() throws Exception {
        ManifestFacts facts = new AndroidManifestFactsExtractor()
                .extract(fixture("exported-explicit.xml"));

        assertThat(facts.packageName()).isEqualTo("oversecured.ovaa");
        assertThat(facts.components()).isEmpty();
        assertThat(facts.permissions()).isEmpty();
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :apps:manifest-facts:test --tests 'com.oversecured.sast.manifestfacts.AndroidManifestFactsExtractorTest.extract_readsPackageName' --no-daemon`

Expected: FAIL with compilation error `cannot find symbol: class AndroidManifestFactsExtractor`.

- [ ] **Step 3: Write minimal implementation**

Create `apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/XmlNames.java`:

```java
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
```

Create `apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractor.java`:

```java
package com.oversecured.sast.manifestfacts;

import com.oversecured.sast.common.ManifestFacts;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

public final class AndroidManifestFactsExtractor {

    public ManifestFacts extract(Path manifestPath) throws IOException {
        Document document = parse(manifestPath);
        String packageName = document.getDocumentElement().getAttribute("package");
        return new ManifestFacts(packageName, List.of(), List.of());
    }

    private static Document parse(Path manifestPath) throws IOException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        try {
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            try (InputStream in = Files.newInputStream(manifestPath)) {
                return factory.newDocumentBuilder().parse(in);
            }
        } catch (SAXException e) {
            throw new IOException("Invalid AndroidManifest.xml: " + manifestPath, e);
        } catch (Exception e) {
            throw new IOException("Could not parse AndroidManifest.xml: " + manifestPath, e);
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :apps:manifest-facts:test --tests 'com.oversecured.sast.manifestfacts.AndroidManifestFactsExtractorTest.extract_readsPackageName' --no-daemon`

Expected: PASS with 1 test.

- [ ] **Step 5: Commit**

```bash
git add apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/XmlNames.java apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractor.java apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractorTest.java apps/manifest-facts/src/test/resources/manifests/exported-explicit.xml
git commit -m "feat(manifest-facts): parse manifest package with hardened DOM"
```

## Task 3: Components, relative names, explicit exported, and component permissions

**Files:**
- Modify: `apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractor.java`
- Modify: `apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractorTest.java`

**Interfaces:**
- Produces `ComponentFact` entries for `activity`, `activity-alias`, `service`, `receiver`, and `provider`.

- [ ] **Step 1: Write the failing test**

Replace the `extract_readsPackageName` test with:

```java
    @Test
    void extract_readsComponents_explicitExported_relativeNames_andPermissions() throws Exception {
        ManifestFacts facts = new AndroidManifestFactsExtractor()
                .extract(fixture("exported-explicit.xml"));

        assertThat(facts.packageName()).isEqualTo("oversecured.ovaa");
        assertThat(facts.components()).extracting(ComponentFact::name)
                .containsExactly(
                        "oversecured.ovaa.activities.DeeplinkActivity",
                        "oversecured.ovaa.SyncService");

        ComponentFact activity = facts.components().get(0);
        assertThat(activity.type()).isEqualTo("activity");
        assertThat(activity.exported()).isTrue();
        assertThat(activity.permission()).isEqualTo("oversecured.ovaa.permission.INTERNAL");
        assertThat(activity.intentFilters()).isEmpty();

        ComponentFact service = facts.components().get(1);
        assertThat(service.type()).isEqualTo("service");
        assertThat(service.exported()).isFalse();
        assertThat(service.permission()).isEqualTo("oversecured.ovaa.permission.INTERNAL");
    }
```

Add imports:

```java
import com.oversecured.sast.common.ComponentFact;
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :apps:manifest-facts:test --tests 'com.oversecured.sast.manifestfacts.AndroidManifestFactsExtractorTest.extract_readsComponents_explicitExported_relativeNames_andPermissions' --no-daemon`

Expected: FAIL because `facts.components()` is empty.

- [ ] **Step 3: Implement component extraction**

Replace `AndroidManifestFactsExtractor.java` with:

```java
package com.oversecured.sast.manifestfacts;

import com.oversecured.sast.common.ComponentFact;
import com.oversecured.sast.common.ManifestFacts;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

public final class AndroidManifestFactsExtractor {

    public ManifestFacts extract(Path manifestPath) throws IOException {
        Document document = parse(manifestPath);
        Element manifest = document.getDocumentElement();
        String packageName = manifest.getAttribute("package");
        Element application = firstChild(manifest, "application");
        String applicationPermission = application == null ? null : XmlNames.androidAttr(application, "permission");

        List<ComponentFact> components = new ArrayList<>();
        if (application != null) {
            for (Element child : childElements(application)) {
                String tag = child.getTagName();
                if (isComponentTag(tag)) {
                    components.add(toComponent(packageName, applicationPermission, child));
                }
            }
        }
        return new ManifestFacts(packageName, List.copyOf(components), List.of());
    }

    private static ComponentFact toComponent(String packageName, String applicationPermission, Element element) {
        String type = element.getTagName().equals("activity-alias") ? "activity" : element.getTagName();
        String name = normalizeComponentName(packageName, XmlNames.androidAttr(element, "name"));
        String exportedRaw = XmlNames.androidAttr(element, "exported");
        boolean exported = exportedRaw != null && Boolean.parseBoolean(exportedRaw);
        String permission = componentPermission(element, type, applicationPermission);
        boolean grantUriPermissions = "provider".equals(type)
                && Boolean.parseBoolean(XmlNames.androidAttr(element, "grantUriPermissions"));
        return new ComponentFact(name, type, exported, List.of(), grantUriPermissions, permission);
    }

    private static String componentPermission(Element element, String type, String applicationPermission) {
        String permission = XmlNames.androidAttr(element, "permission");
        if (permission != null) {
            return permission;
        }
        if ("provider".equals(type)) {
            String read = XmlNames.androidAttr(element, "readPermission");
            String write = XmlNames.androidAttr(element, "writePermission");
            if (read != null && write != null) {
                return "read=" + read + ";write=" + write;
            }
            if (read != null) {
                return "read=" + read;
            }
            if (write != null) {
                return "write=" + write;
            }
        }
        return applicationPermission;
    }

    private static boolean isComponentTag(String tag) {
        return tag.equals("activity")
                || tag.equals("activity-alias")
                || tag.equals("service")
                || tag.equals("receiver")
                || tag.equals("provider");
    }

    static String normalizeComponentName(String packageName, String rawName) {
        if (rawName == null || rawName.isBlank()) {
            return "";
        }
        if (rawName.startsWith(".")) {
            return packageName + rawName;
        }
        if (!rawName.contains(".")) {
            return packageName + "." + rawName;
        }
        return rawName;
    }

    private static Element firstChild(Element parent, String tagName) {
        for (Element child : childElements(parent)) {
            if (child.getTagName().equals(tagName)) {
                return child;
            }
        }
        return null;
    }

    private static List<Element> childElements(Element parent) {
        List<Element> elements = new ArrayList<>();
        NodeList children = parent.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            Node node = children.item(i);
            if (node instanceof Element element) {
                elements.add(element);
            }
        }
        return elements;
    }

    private static Document parse(Path manifestPath) throws IOException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        try {
            factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setXIncludeAware(false);
            factory.setExpandEntityReferences(false);
            try (InputStream in = Files.newInputStream(manifestPath)) {
                return factory.newDocumentBuilder().parse(in);
            }
        } catch (SAXException e) {
            throw new IOException("Invalid AndroidManifest.xml: " + manifestPath, e);
        } catch (Exception e) {
            throw new IOException("Could not parse AndroidManifest.xml: " + manifestPath, e);
        }
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :apps:manifest-facts:test --tests 'com.oversecured.sast.manifestfacts.AndroidManifestFactsExtractorTest.extract_readsComponents_explicitExported_relativeNames_andPermissions' --no-daemon`

Expected: PASS with 1 test.

- [ ] **Step 5: Commit**

```bash
git add apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractor.java apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractorTest.java
git commit -m "feat(manifest-facts): extract components and explicit exported flags"
```

## Task 4: Pre-31 default exported logic via intent-filter

**Files:**
- Modify: `apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractor.java`
- Create: `apps/manifest-facts/src/test/resources/manifests/exported-defaults.xml`
- Modify: `apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractorTest.java`

**Interfaces:**
- Produces default exported booleans when `android:exported` is absent.

- [ ] **Step 1: Add fixture and failing test**

Create `apps/manifest-facts/src/test/resources/manifests/exported-defaults.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="oversecured.defaults">
    <application>
        <activity android:name=".FilteredActivity">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
            </intent-filter>
        </activity>
        <receiver android:name=".BootReceiver">
            <intent-filter>
                <action android:name="android.intent.action.BOOT_COMPLETED" />
            </intent-filter>
        </receiver>
        <service android:name=".PlainService" />
        <provider android:name=".FilesProvider" android:authorities="oversecured.defaults.files" />
        <activity android:name=".ExplicitFalseActivity" android:exported="false">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

Append to `AndroidManifestFactsExtractorTest.java`:

```java
    @Test
    void extract_appliesPre31DefaultExportedFromIntentFilters() throws Exception {
        ManifestFacts facts = new AndroidManifestFactsExtractor()
                .extract(fixture("exported-defaults.xml"));

        assertThat(facts.components()).extracting(ComponentFact::name, ComponentFact::exported)
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple("oversecured.defaults.FilteredActivity", true),
                        org.assertj.core.groups.Tuple.tuple("oversecured.defaults.BootReceiver", true),
                        org.assertj.core.groups.Tuple.tuple("oversecured.defaults.PlainService", false),
                        org.assertj.core.groups.Tuple.tuple("oversecured.defaults.FilesProvider", false),
                        org.assertj.core.groups.Tuple.tuple("oversecured.defaults.ExplicitFalseActivity", false));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :apps:manifest-facts:test --tests 'com.oversecured.sast.manifestfacts.AndroidManifestFactsExtractorTest.extract_appliesPre31DefaultExportedFromIntentFilters' --no-daemon`

Expected: FAIL because absent `android:exported` currently yields false even when an intent-filter exists.

- [ ] **Step 3: Implement default exported logic**

In `AndroidManifestFactsExtractor.java`, replace:

```java
        String exportedRaw = XmlNames.androidAttr(element, "exported");
        boolean exported = exportedRaw != null && Boolean.parseBoolean(exportedRaw);
```

with:

```java
        boolean hasIntentFilter = hasChild(element, "intent-filter");
        String exportedRaw = XmlNames.androidAttr(element, "exported");
        boolean exported = exportedRaw == null
                ? defaultExported(type, hasIntentFilter)
                : Boolean.parseBoolean(exportedRaw);
```

Add these helper methods before `isComponentTag`:

```java
    private static boolean defaultExported(String type, boolean hasIntentFilter) {
        if ("provider".equals(type)) {
            return false;
        }
        return hasIntentFilter;
    }

    private static boolean hasChild(Element parent, String tagName) {
        return firstChild(parent, tagName) != null;
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :apps:manifest-facts:test --tests 'com.oversecured.sast.manifestfacts.AndroidManifestFactsExtractorTest.extract_appliesPre31DefaultExportedFromIntentFilters' --no-daemon`

Expected: PASS with 1 test.

- [ ] **Step 5: Commit**

```bash
git add apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractor.java apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractorTest.java apps/manifest-facts/src/test/resources/manifests/exported-defaults.xml
git commit -m "feat(manifest-facts): apply exported defaults from intent filters"
```

## Task 5: Intent-filter actions and data scheme/host extraction

**Files:**
- Modify: `apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractor.java`
- Create: `apps/manifest-facts/src/test/resources/manifests/deeplink-data.xml`
- Modify: `apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractorTest.java`

**Interfaces:**
- Produces `IntentFilterFact(actions, schemes, hosts)` for every component `intent-filter`.

- [ ] **Step 1: Add fixture and failing test**

Create `apps/manifest-facts/src/test/resources/manifests/deeplink-data.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="oversecured.deeplink">
    <application>
        <activity android:name=".DeeplinkActivity">
            <intent-filter>
                <action android:name="android.intent.action.VIEW" />
                <category android:name="android.intent.category.DEFAULT" />
                <category android:name="android.intent.category.BROWSABLE" />
                <data android:scheme="oversecured" android:host="ovaa" />
                <data android:scheme="https" android:host="example.com" />
            </intent-filter>
        </activity>
    </application>
</manifest>
```

Append to `AndroidManifestFactsExtractorTest.java`:

```java
    @Test
    void extract_readsIntentFilterActionsAndDataSchemesHosts() throws Exception {
        ManifestFacts facts = new AndroidManifestFactsExtractor()
                .extract(fixture("deeplink-data.xml"));

        ComponentFact component = facts.components().get(0);
        assertThat(component.exported()).isTrue();
        assertThat(component.intentFilters()).hasSize(1);

        IntentFilterFact filter = component.intentFilters().get(0);
        assertThat(filter.actions()).containsExactly("android.intent.action.VIEW");
        assertThat(filter.schemes()).containsExactly("https", "oversecured");
        assertThat(filter.hosts()).containsExactly("example.com", "ovaa");
    }
```

Add import:

```java
import com.oversecured.sast.common.IntentFilterFact;
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :apps:manifest-facts:test --tests 'com.oversecured.sast.manifestfacts.AndroidManifestFactsExtractorTest.extract_readsIntentFilterActionsAndDataSchemesHosts' --no-daemon`

Expected: FAIL because `component.intentFilters()` is empty.

- [ ] **Step 3: Implement intent-filter extraction**

In `AndroidManifestFactsExtractor.java`, add imports:

```java
import com.oversecured.sast.common.IntentFilterFact;
import java.util.SortedSet;
import java.util.TreeSet;
```

In `toComponent`, replace:

```java
        return new ComponentFact(name, type, exported, List.of(), grantUriPermissions, permission);
```

with:

```java
        return new ComponentFact(name, type, exported, intentFilters(element), grantUriPermissions, permission);
```

Add helper methods before `componentPermission`:

```java
    private static List<IntentFilterFact> intentFilters(Element component) {
        List<IntentFilterFact> filters = new ArrayList<>();
        for (Element child : childElements(component)) {
            if (!child.getTagName().equals("intent-filter")) {
                continue;
            }
            SortedSet<String> actions = new TreeSet<>();
            SortedSet<String> schemes = new TreeSet<>();
            SortedSet<String> hosts = new TreeSet<>();
            for (Element filterChild : childElements(child)) {
                switch (filterChild.getTagName()) {
                    case "action" -> addIfPresent(actions, XmlNames.androidAttr(filterChild, "name"));
                    case "data" -> {
                        addIfPresent(schemes, XmlNames.androidAttr(filterChild, "scheme"));
                        addIfPresent(hosts, XmlNames.androidAttr(filterChild, "host"));
                    }
                    case "category" -> {
                        String ignored = XmlNames.androidAttr(filterChild, "name");
                    }
                    default -> {
                        String ignored = filterChild.getTagName();
                    }
                }
            }
            filters.add(new IntentFilterFact(
                    List.copyOf(actions),
                    List.copyOf(schemes),
                    List.copyOf(hosts)));
        }
        return List.copyOf(filters);
    }

    private static void addIfPresent(SortedSet<String> values, String value) {
        if (value != null && !value.isBlank()) {
            values.add(value);
        }
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :apps:manifest-facts:test --tests 'com.oversecured.sast.manifestfacts.AndroidManifestFactsExtractorTest.extract_readsIntentFilterActionsAndDataSchemesHosts' --no-daemon`

Expected: PASS with 1 test.

- [ ] **Step 5: Commit**

```bash
git add apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractor.java apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractorTest.java apps/manifest-facts/src/test/resources/manifests/deeplink-data.xml
git commit -m "feat(manifest-facts): extract intent filter deeplink facts"
```

## Task 6: Manifest permissions and provider permission variants

**Files:**
- Modify: `apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractor.java`
- Create: `apps/manifest-facts/src/test/resources/manifests/permissions-and-provider.xml`
- Modify: `apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractorTest.java`

**Interfaces:**
- Produces `ManifestFacts.permissions()` and provider permission strings.

- [ ] **Step 1: Add fixture and failing test**

Create `apps/manifest-facts/src/test/resources/manifests/permissions-and-provider.xml`:

```xml
<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="oversecured.perms">
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission-sdk-23 android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <permission android:name="oversecured.perms.permission.SIGNATURE" />
    <application>
        <provider
            android:name=".FilesProvider"
            android:authorities="oversecured.perms.files"
            android:readPermission="oversecured.perms.permission.READ"
            android:writePermission="oversecured.perms.permission.WRITE" />
        <receiver
            android:name=".ProtectedReceiver"
            android:permission="oversecured.perms.permission.SIGNATURE" />
    </application>
</manifest>
```

Append to `AndroidManifestFactsExtractorTest.java`:

```java
    @Test
    void extract_readsManifestPermissionsAndProviderReadWritePermissions() throws Exception {
        ManifestFacts facts = new AndroidManifestFactsExtractor()
                .extract(fixture("permissions-and-provider.xml"));

        assertThat(facts.permissions()).containsExactly(
                "android.permission.INTERNET",
                "android.permission.READ_EXTERNAL_STORAGE",
                "oversecured.perms.permission.SIGNATURE");

        assertThat(facts.components()).extracting(ComponentFact::name, ComponentFact::grantUriPermissions, ComponentFact::permission)
                .containsExactly(
                        org.assertj.core.groups.Tuple.tuple(
                                "oversecured.perms.FilesProvider",
                                true,
                                "read=oversecured.perms.permission.READ;write=oversecured.perms.permission.WRITE"),
                        org.assertj.core.groups.Tuple.tuple(
                                "oversecured.perms.ProtectedReceiver",
                                false,
                                "oversecured.perms.permission.SIGNATURE"));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :apps:manifest-facts:test --tests 'com.oversecured.sast.manifestfacts.AndroidManifestFactsExtractorTest.extract_readsManifestPermissionsAndProviderReadWritePermissions' --no-daemon`

Expected: FAIL because `ManifestFacts.permissions()` is empty.

- [ ] **Step 3: Implement permissions extraction**

In `AndroidManifestFactsExtractor.java`, replace:

```java
        return new ManifestFacts(packageName, List.copyOf(components), List.of());
```

with:

```java
        return new ManifestFacts(packageName, List.copyOf(components), manifestPermissions(manifest));
```

Add helper method before `toComponent`:

```java
    private static List<String> manifestPermissions(Element manifest) {
        SortedSet<String> permissions = new TreeSet<>();
        for (Element child : childElements(manifest)) {
            String tag = child.getTagName();
            if (tag.equals("uses-permission")
                    || tag.equals("uses-permission-sdk-23")
                    || tag.equals("permission")) {
                addIfPresent(permissions, XmlNames.androidAttr(child, "name"));
            }
        }
        return List.copyOf(permissions);
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :apps:manifest-facts:test --tests 'com.oversecured.sast.manifestfacts.AndroidManifestFactsExtractorTest.extract_readsManifestPermissionsAndProviderReadWritePermissions' --no-daemon`

Expected: PASS with 1 test.

- [ ] **Step 5: Commit**

```bash
git add apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractor.java apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractorTest.java apps/manifest-facts/src/test/resources/manifests/permissions-and-provider.xml
git commit -m "feat(manifest-facts): extract manifest and provider permissions"
```

## Task 7: Library API writes deterministic `facts.json`

**Files:**
- Create: `apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/ManifestFactsApp.java`
- Create: `apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/ManifestFactsAppTest.java`

**Interfaces:**
- Produces `ManifestFactsApp.extract(Path manifest, Path out) throws IOException`, used by CLI and orchestrator activity code.

- [ ] **Step 1: Write the failing test**

Create `apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/ManifestFactsAppTest.java`:

```java
package com.oversecured.sast.manifestfacts;

import com.oversecured.sast.common.Json;
import com.oversecured.sast.common.ManifestFacts;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.assertj.core.api.Assertions.assertThat;

class ManifestFactsAppTest {

    @TempDir
    Path tempDir;

    private Path fixture(String name) throws Exception {
        return Paths.get(getClass().getResource("/manifests/" + name).toURI());
    }

    @Test
    void extract_writesFactsJsonThatDeserializesIntoSharedManifestFacts() throws Exception {
        Path out = tempDir.resolve("nested/facts.json");

        ManifestFacts returned = new ManifestFactsApp().extract(fixture("deeplink-data.xml"), out);
        ManifestFacts fromDisk = Json.read(Files.readAllBytes(out), ManifestFacts.class);

        assertThat(fromDisk).isEqualTo(returned);
        assertThat(fromDisk.packageName()).isEqualTo("oversecured.deeplink");
        assertThat(Files.readString(out)).contains("\"packageName\"");
        assertThat(Files.readString(out)).contains("\"intentFilters\"");
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :apps:manifest-facts:test --tests 'com.oversecured.sast.manifestfacts.ManifestFactsAppTest' --no-daemon`

Expected: FAIL with compilation error `cannot find symbol: class ManifestFactsApp`.

- [ ] **Step 3: Implement library API**

Create `apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/ManifestFactsApp.java`:

```java
package com.oversecured.sast.manifestfacts;

import com.oversecured.sast.common.Json;
import com.oversecured.sast.common.ManifestFacts;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public final class ManifestFactsApp {
    private final AndroidManifestFactsExtractor extractor;

    public ManifestFactsApp() {
        this(new AndroidManifestFactsExtractor());
    }

    ManifestFactsApp(AndroidManifestFactsExtractor extractor) {
        this.extractor = extractor;
    }

    public ManifestFacts extract(Path manifest, Path out) throws IOException {
        ManifestFacts facts = extractor.extract(manifest);
        Path parent = out.toAbsolutePath().getParent();
        if (parent != null) {
            Files.createDirectories(parent);
        }
        Files.write(out, Json.writeBytes(facts));
        return facts;
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :apps:manifest-facts:test --tests 'com.oversecured.sast.manifestfacts.ManifestFactsAppTest' --no-daemon`

Expected: PASS with 1 test.

- [ ] **Step 5: Commit**

```bash
git add apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/ManifestFactsApp.java apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/ManifestFactsAppTest.java
git commit -m "feat(manifest-facts): write shared facts json artifact"
```

## Task 8: `mfacts` CLI

**Files:**
- Create: `apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/ManifestFactsCommand.java`
- Create: `apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/ManifestFactsCommandTest.java`

**Interfaces:**
- Produces CLI entrypoint `mfacts --manifest <AndroidManifest.xml> --out <facts.json>`.

- [ ] **Step 1: Write the failing test**

Create `apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/ManifestFactsCommandTest.java`:

```java
package com.oversecured.sast.manifestfacts;

import com.oversecured.sast.common.Json;
import com.oversecured.sast.common.ManifestFacts;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;

import static org.assertj.core.api.Assertions.assertThat;

class ManifestFactsCommandTest {

    @TempDir
    Path tempDir;

    private Path fixture(String name) throws Exception {
        return Paths.get(getClass().getResource("/manifests/" + name).toURI());
    }

    @Test
    void command_writesFactsJsonFromManifestArgument() throws Exception {
        Path out = tempDir.resolve("facts.json");

        int exit = new CommandLine(new ManifestFactsCommand()).execute(
                "--manifest", fixture("deeplink-data.xml").toString(),
                "--out", out.toString());

        assertThat(exit).isEqualTo(0);
        ManifestFacts facts = Json.read(Files.readAllBytes(out), ManifestFacts.class);
        assertThat(facts.packageName()).isEqualTo("oversecured.deeplink");
        assertThat(facts.components()).hasSize(1);
    }

    @Test
    void command_missingManifestReturnsUsageError() {
        int exit = new CommandLine(new ManifestFactsCommand()).execute("--out", "facts.json");

        assertThat(exit).isEqualTo(CommandLine.ExitCode.USAGE);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `./gradlew :apps:manifest-facts:test --tests 'com.oversecured.sast.manifestfacts.ManifestFactsCommandTest' --no-daemon`

Expected: FAIL with compilation error `cannot find symbol: class ManifestFactsCommand`.

- [ ] **Step 3: Implement CLI**

Create `apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/ManifestFactsCommand.java`:

```java
package com.oversecured.sast.manifestfacts;

import java.nio.file.Path;
import java.util.concurrent.Callable;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(
        name = "mfacts",
        mixinStandardHelpOptions = true,
        description = "Extract shared manifest facts from AndroidManifest.xml")
public final class ManifestFactsCommand implements Callable<Integer> {

    @Option(names = "--manifest", required = true, description = "Path to AndroidManifest.xml")
    private Path manifest;

    @Option(names = "--out", required = true, description = "Path to output facts.json")
    private Path out;

    @Override
    public Integer call() throws Exception {
        new ManifestFactsApp().extract(manifest, out);
        return CommandLine.ExitCode.OK;
    }

    public static void main(String[] args) {
        int exit = new CommandLine(new ManifestFactsCommand()).execute(args);
        System.exit(exit);
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `./gradlew :apps:manifest-facts:test --tests 'com.oversecured.sast.manifestfacts.ManifestFactsCommandTest' --no-daemon`

Expected: PASS with 2 tests.

- [ ] **Step 5: Verify installed CLI name**

Run: `./gradlew :apps:manifest-facts:installDist --no-daemon`

Expected: PASS and creates `apps/manifest-facts/build/install/mfacts/bin/mfacts`.

Run:

```bash
apps/manifest-facts/build/install/mfacts/bin/mfacts \
  --manifest apps/manifest-facts/src/test/resources/manifests/deeplink-data.xml \
  --out apps/manifest-facts/build/tmp/facts.json
```

Expected: exit code 0 and `apps/manifest-facts/build/tmp/facts.json` contains `"packageName" : "oversecured.deeplink"`.

- [ ] **Step 6: Commit**

```bash
git add apps/manifest-facts/src/main/java/com/oversecured/sast/manifestfacts/ManifestFactsCommand.java apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/ManifestFactsCommandTest.java
git commit -m "feat(manifest-facts): add mfacts cli"
```

## Task 9: End-to-end coverage, malformed XML, and no-findings boundary

**Files:**
- Modify: `apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractorTest.java`
- Modify: `apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/ManifestFactsAppTest.java`

**Interfaces:**
- Produces final verification that extracted facts cover exported logic, components, permissions, intent filters, and data scheme/host; confirms malformed XML fails without findings output.

- [ ] **Step 1: Add end-to-end extraction test**

Append to `AndroidManifestFactsExtractorTest.java`:

```java
    @Test
    void endToEnd_extractsFactsNeededByTaintAndMisconfigConsumers() throws Exception {
        ManifestFacts facts = new AndroidManifestFactsExtractor()
                .extract(fixture("deeplink-data.xml"));

        assertThat(facts.packageName()).isEqualTo("oversecured.deeplink");
        assertThat(facts.components()).hasSize(1);
        ComponentFact deeplink = facts.components().get(0);
        assertThat(deeplink.type()).isEqualTo("activity");
        assertThat(deeplink.exported()).isTrue();
        assertThat(deeplink.permission()).isNull();
        assertThat(deeplink.intentFilters()).hasSize(1);
        assertThat(deeplink.intentFilters().get(0).actions())
                .containsExactly("android.intent.action.VIEW");
        assertThat(deeplink.intentFilters().get(0).schemes())
                .containsExactly("https", "oversecured");
        assertThat(deeplink.intentFilters().get(0).hosts())
                .containsExactly("example.com", "ovaa");
    }
```

- [ ] **Step 2: Add malformed XML test**

Append to `ManifestFactsAppTest.java`:

```java
    @Test
    void extract_malformedXmlDoesNotWriteFactsJson() throws Exception {
        Path badManifest = tempDir.resolve("AndroidManifest.xml");
        Path out = tempDir.resolve("facts.json");
        Files.writeString(badManifest, "<manifest><application></manifest>");

        org.assertj.core.api.Assertions.assertThatThrownBy(
                        () -> new ManifestFactsApp().extract(badManifest, out))
                .isInstanceOf(java.io.IOException.class)
                .hasMessageContaining("AndroidManifest.xml");
        assertThat(out).doesNotExist();
    }
```

- [ ] **Step 3: Run all module tests**

Run: `./gradlew :apps:manifest-facts:test --no-daemon`

Expected: PASS with all `AndroidManifestFactsExtractorTest`, `ManifestFactsAppTest`, and `ManifestFactsCommandTest` tests green.

- [ ] **Step 4: Run cross-module verification**

Run: `./gradlew :common:test :apps:manifest-facts:test :apps:manifest-facts:installDist --no-daemon`

Expected: PASS. This verifies the shared `ManifestFacts` schema and the runnable `mfacts` distribution together.

- [ ] **Step 5: Commit**

```bash
git add apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/AndroidManifestFactsExtractorTest.java apps/manifest-facts/src/test/java/com/oversecured/sast/manifestfacts/ManifestFactsAppTest.java
git commit -m "test(manifest-facts): cover end-to-end facts extraction"
```

## Self-Review

**1. Spec coverage:** CLI `mfacts --manifest <AndroidManifest.xml> --out <facts.json>` is implemented in Task 8; library API for orchestrator use is Task 7; `sources/AndroidManifest.xml` is supported because the CLI accepts arbitrary manifest paths; output is shared `ManifestFacts` serialized through `Json` in Task 7; exported explicit Android 12 and pre-31 intent-filter defaults are Tasks 3 and 4; components, permissions, intent filters, data scheme/host are Tasks 3, 5, and 6; no analyzer findings are emitted anywhere.

**2. Completeness scan:** Every file introduced by the plan has concrete content or exact edit instructions.

**3. Type consistency:** `ManifestFacts`, `ComponentFact`, `IntentFilterFact`, and `Json` are always imported from `com.oversecured.sast.common`; module package root remains `com.oversecured.sast.manifestfacts`; Gradle task names use `:apps:manifest-facts`; CLI command name is `mfacts`.

**4. Consumer compatibility:** Facts use only the shared fields available to taint and manifest-misconfig consumers: package name, component name/type/exported/permission, intent-filter actions/schemes/hosts, and manifest permissions. Categories and provider authorities are not serialized because the shared `common` schema does not expose fields for them.
