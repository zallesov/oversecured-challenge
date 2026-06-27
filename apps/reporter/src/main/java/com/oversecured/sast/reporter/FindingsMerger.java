package com.oversecured.sast.reporter;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oversecured.sast.common.Finding;
import com.oversecured.sast.common.FindingsDoc;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Reads multiple analyzer findings.json files and concatenates their findings. */
public final class FindingsMerger {

    private static final ObjectMapper MAPPER =
            new ObjectMapper().configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    public static ObjectMapper mapper() {
        return MAPPER;
    }

    public List<Finding> merge(List<Path> findingsFiles) throws IOException {
        List<Finding> merged = new ArrayList<>();
        for (Path file : findingsFiles) {
            FindingsDoc doc = MAPPER.readValue(Files.readAllBytes(file), FindingsDoc.class);
            if (doc.findings() != null) {
                merged.addAll(doc.findings());
            }
        }
        return merged;
    }
}
