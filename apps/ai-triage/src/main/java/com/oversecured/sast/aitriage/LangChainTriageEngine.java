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

    /** Structured-output AI service. LangChain4j derives a JSON schema from TriageResult. */
    interface TriageAiService {
        @SystemMessage(TriagePrompt.SYSTEM)
        TriageResult triage(@UserMessage String findings);
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
                .build();
        TriageAiService service = AiServices.builder(TriageAiService.class)
                .chatModel(chatModel)
                .tools(new SourceTools(sourcesDir))
                .build();
        return new LangChainTriageEngine(service, model);
    }

    @Override
    public TriageResult triage(List<TriageFinding> findings) {
        TriageResult raw = service.triage(TriagePrompt.renderFindings(findings));
        return new TriageResult(model, Instant.now().toString(), raw.summary(), raw.items());
    }

    @Override
    public String modelName() {
        return model;
    }
}
