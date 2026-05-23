package com.example.api.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.core.JsonProcessingException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.stereotype.Service;

/**
 * SC-01: HAPPY PATH scenario (Jackson — no breaking changes)
 * SC-05: HARDCODED VERSION scenario (jackson-databind 2.9.8 in api/pom.xml)
 *
 * CVE-2020-25649: jackson-databind 2.9.8 vulnerable to XXE injection.
 * Fix: 2.9.8 → 2.9.10.4+ (patch upgrade, no API changes)
 *
 * Expected FortifyAI behaviour:
 *   API Diff    → has_breaking_changes=False (2.9.8 → 2.9.10.4 is patch)
 *   AI Reasoning → confidence=high, pre_fix_required=False
 *   Routing     → adr_fix directly (high confidence, no code change needed)
 *
 * Note: ADR fix type = HARDCODED — updates <version>2.9.8</version>
 *       inline in api/pom.xml (not a property reference)
 */
@Service
public class UserService {

    private final ObjectMapper objectMapper;

    public UserService() {
        this.objectMapper = new ObjectMapper();
        this.objectMapper.configure(
            DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false
        );
    }

    public String serialize(Object obj) throws JsonProcessingException {
        // ObjectMapper API stable from 2.9.x → 2.9.10.x (patch upgrade)
        return objectMapper.writeValueAsString(obj);
    }

    public <T> T deserialize(String json, Class<T> clazz) throws JsonProcessingException {
        // ⚠️  Vulnerable deserialization path in 2.9.8 — CVE-2020-25649
        return objectMapper.readValue(json, clazz);
    }

    public ApplicationContext createContext() {
        // spring-context usage — exercises SC-01/SC-04 calling file detection
        return new AnnotationConfigApplicationContext();
    }
}
