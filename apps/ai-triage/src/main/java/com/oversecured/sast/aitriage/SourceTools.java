package com.oversecured.sast.aitriage;

import dev.langchain4j.agent.tool.P;
import dev.langchain4j.agent.tool.Tool;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

/** Filesystem tools exposed to the agent, jailed to the decompiled sources root. */
public final class SourceTools {

    private static final int MAX_MATCHES = 50;

    private final Path root;

    public SourceTools(Path sourcesRoot) {
        this.root = sourcesRoot.toAbsolutePath().normalize();
    }

    @Tool("Read a source file (paths relative to the sources root). "
            + "Optional 1-based inclusive start/end line range.")
    public String readFile(
            @P("relative file path") String relpath,
            @P(value = "start line, 1-based, inclusive; null for start of file", required = false) Integer start,
            @P(value = "end line, 1-based, inclusive; null for end of file", required = false) Integer end) {
        Path resolved = jail(relpath);
        if (resolved == null) {
            return "ERROR: path escapes sources root";
        }
        if (!Files.isRegularFile(resolved)) {
            return "ERROR: file not found: " + relpath;
        }
        List<String> lines = readLines(resolved);
        int from = start == null ? 1 : Math.max(1, start);
        int to = end == null ? lines.size() : Math.min(lines.size(), end);
        StringBuilder sb = new StringBuilder();
        for (int i = from; i <= to; i++) {
            if (sb.length() > 0) {
                sb.append("\n");
            }
            sb.append(i).append("\t").append(lines.get(i - 1));
        }
        return sb.toString();
    }

    @Tool("List the entries of a directory relative to the sources root.")
    public String listDir(@P("relative directory path") String relpath) {
        Path resolved = jail(relpath);
        if (resolved == null) {
            return "ERROR: path escapes sources root";
        }
        if (!Files.isDirectory(resolved)) {
            return "ERROR: directory not found: " + relpath;
        }
        try (Stream<Path> entries = Files.list(resolved)) {
            return entries.map(p -> p.getFileName().toString()).sorted().reduce((a, b) -> a + "\n" + b).orElse("");
        } catch (IOException e) {
            return "ERROR: " + e.getMessage();
        }
    }

    @Tool("Search all .java files under the sources root for a substring. "
            + "Returns up to 50 'file:line: text' matches.")
    public String searchCode(@P("substring to search for") String query) {
        List<String> matches = new ArrayList<>();
        try (Stream<Path> files = Files.walk(root)) {
            files.filter(Files::isRegularFile)
                    .filter(p -> p.toString().endsWith(".java"))
                    .forEach(p -> collectMatches(p, query, matches));
        } catch (IOException e) {
            return "ERROR: " + e.getMessage();
        }
        return String.join("\n", matches);
    }

    private void collectMatches(Path file, String query, List<String> matches) {
        if (matches.size() >= MAX_MATCHES) {
            return;
        }
        List<String> lines = readLines(file);
        String rel = root.relativize(file).toString();
        for (int i = 0; i < lines.size() && matches.size() < MAX_MATCHES; i++) {
            if (lines.get(i).contains(query)) {
                matches.add(rel + ":" + (i + 1) + ": " + lines.get(i).trim());
            }
        }
    }

    private Path jail(String relpath) {
        if (relpath == null) {
            return null;
        }
        Path resolved = root.resolve(relpath).normalize();
        return resolved.startsWith(root) ? resolved : null;
    }

    private List<String> readLines(Path file) {
        try {
            return Files.readAllLines(file);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
