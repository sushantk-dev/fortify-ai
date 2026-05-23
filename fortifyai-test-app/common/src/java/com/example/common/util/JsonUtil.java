package com.example.common.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import java.util.Map;

/**
 * SC-01/05: HAPPY PATH + HARDCODED VERSION scenario
 *
 * Uses jackson-core 2.9.8 (CVE-2020-25649).
 * Patch upgrade to 2.9.10.4 — ObjectMapper/JsonProcessingException API unchanged.
 */
public final class JsonUtil {

    private static final ObjectMapper MAPPER = new ObjectMapper()
        .enable(SerializationFeature.INDENT_OUTPUT);

    private JsonUtil() {}

    public static String toJson(Object obj) throws JsonProcessingException {
        return MAPPER.writeValueAsString(obj);
    }

    public static <T> T fromJson(String json, Class<T> clazz) throws JsonProcessingException {
        return MAPPER.readValue(json, clazz);
    }

    public static Map<String, Object> toMap(String json) throws JsonProcessingException {
        return MAPPER.readValue(json, new TypeReference<Map<String, Object>>() {});
    }
}
