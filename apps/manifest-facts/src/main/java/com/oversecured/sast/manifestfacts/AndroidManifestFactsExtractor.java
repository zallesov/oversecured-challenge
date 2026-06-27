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
