package com.oversecured.sast.aitriage;

import dev.langchain4j.model.chat.ChatModel;
import dev.langchain4j.model.openai.OpenAiChatModel;
import dev.langchain4j.service.AiServices;
import dev.langchain4j.service.SystemMessage;
import dev.langchain4j.service.UserMessage;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

/** Production triage engine backed by LangChain4j over an OpenAI-compatible (OpenRouter) model. */
public final class LangChainTriageEngine implements TriageEngine {

    /**
     * The agentic service. Returns raw assistant text rather than a POJO: over an
     * OpenAI-compatible passthrough (OpenRouter → Anthropic) the model wraps its JSON in
     * prose / a ```json fence and LangChain4j's built-in POJO parser rejects it. We extract
     * and parse the JSON ourselves in {@link #triage}.
     */
    interface TriageAiService {
        @SystemMessage(TriagePrompt.SYSTEM)
        String triage(@UserMessage String findings);
    }

    private final TriageAiService service;
    private final String model;

    private LangChainTriageEngine(TriageAiService service, String model) {
        this.service = service;
        this.model = model;
    }

    public static TriageEngine create(String apiKey, String baseUrl, String model, Path sourcesDir) {
        if (apiKey == null || apiKey.isBlank()) {
            return null;
        }
        ChatModel chatModel = OpenAiChatModel.builder()
                .baseUrl(baseUrl)
                .apiKey(apiKey)
                .modelName(model)
                // Force valid-JSON output. Over OpenRouter's OpenAI-compatible shim the model
                // otherwise wraps its answer in prose / a ```json fence (or omits JSON entirely),
                // which breaks parsing. json_object mode makes the final message a bare JSON object.
                // Supported by the structured-output Claude models (Haiku/Sonnet/Opus 4.5+).
                .responseFormat("json_object")
                .build();
        TriageAiService service = AiServices.builder(TriageAiService.class)
                .chatModel(chatModel)
                .tools(new SourceTools(sourcesDir))
                .build();
        return new LangChainTriageEngine(service, model);
    }

    @Override
    public TriageResult triage(List<TriageFinding> findings) {
        String response = service.triage(TriagePrompt.renderFindings(findings));
        TriageResult raw = TriageJson.read(extractJson(response));
        return new TriageResult(model, Instant.now().toString(), raw.summary(), raw.items());
    }

    @Override
    public String modelName() {
        return model;
    }

    /**
     * Pull a JSON object out of a possibly chatty assistant reply: prefer a fenced
     * ```json block, otherwise take the span from the first '{' to the last '}'.
     */
    static String extractJson(String response) {
        if (response == null) {
            throw new IllegalArgumentException("empty model response");
        }
        int fence = response.indexOf("```");
        if (fence >= 0) {
            int start = response.indexOf('\n', fence);
            int end = response.indexOf("```", fence + 3);
            if (start >= 0 && end > start) {
                String inner = response.substring(start + 1, end).trim();
                if (inner.startsWith("{")) {
                    return inner;
                }
            }
        }
        int open = response.indexOf('{');
        int close = response.lastIndexOf('}');
        if (open >= 0 && close > open) {
            return response.substring(open, close + 1);
        }
        throw new IllegalArgumentException("no JSON object in model response");
    }
}
