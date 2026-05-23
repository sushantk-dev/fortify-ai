package com.example.api.controller;

import org.springframework.web.bind.WebDataBinder;
import org.springframework.web.bind.annotation.InitBinder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * SC-02: BREAKING CHANGE scenario
 *
 * This controller calls two WebDataBinder methods that are REMOVED in
 * spring-context 6.x:
 *   - setDisallowedFields()  removed in 6.0.0
 *   - isAllowed()            removed in 6.0.0
 *
 * Expected FortifyAI behaviour after upgrade to 6.1.20:
 *   API Diff    → has_breaking_changes=True, breaking_count=2
 *   AI Reasoning → confidence=medium, pre_fix_required=True
 *                  at_risk_lines=["DataBinderController.java:35",
 *                                 "DataBinderController.java:37"]
 *   Routing     → ai_code_fix first, then adr_fix
 *
 * Fix the AI agent should generate:
 *   REMOVE binder.setDisallowedFields(...) call (field is no longer needed)
 *   REMOVE binder.isAllowed(...) call (method removed, use allowedFields instead)
 */
@RestController
@RequestMapping("/api/users")
public class DataBinderController {

    @InitBinder
    public void initBinder(WebDataBinder binder) {
        // ⚠️  BREAKING: setDisallowedFields() removed in spring-context 6.x
        binder.setDisallowedFields("id", "createdAt", "updatedAt");      // line 35
        // ⚠️  BREAKING: isAllowed() removed in spring-context 6.x
        boolean allowed = binder.isAllowed("username");                   // line 37
        if (!allowed) {
            throw new IllegalArgumentException("Field not allowed");
        }
    }

    @PostMapping
    public String createUser(@RequestBody String body) {
        return "created: " + body;
    }

    @PostMapping("/admin")
    public String createAdminUser(@RequestBody String body) {
        // SC-02: Another call to the same broken API (tests multi-line detection)
        return "admin created";
    }
}
