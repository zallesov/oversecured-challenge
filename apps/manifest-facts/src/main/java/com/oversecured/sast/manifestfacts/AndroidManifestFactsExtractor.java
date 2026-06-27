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
