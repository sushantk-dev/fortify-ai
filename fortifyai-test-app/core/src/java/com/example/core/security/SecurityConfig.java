package com.example.core.security;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.ServerConnector;
import org.eclipse.jetty.http.HttpVersion;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * SC-01: HAPPY PATH scenario (Jetty — patch upgrade, no breaking changes)
 *
 * CVE-2023-44487: jetty-http 12.0.0 vulnerable to HTTP/2 Rapid Reset.
 * Fix: 12.0.0 → 12.0.7 (patch upgrade, Server/ServerConnector APIs stable)
 *
 * Expected FortifyAI behaviour:
 *   API Diff    → has_breaking_changes=False (patch upgrade)
 *   AI Reasoning → confidence=high, pre_fix_required=False
 *   Routing     → adr_fix directly
 */
@Configuration
public class SecurityConfig {

    @Bean
    public Server jettyServer() {
        // Jetty Server API — stable across 12.0.x patch versions
        Server server = new Server();
        ServerConnector connector = new ServerConnector(server);
        connector.setPort(8080);
        server.addConnector(connector);
        return server;
    }

    public HttpVersion getHttpVersion() {
        // HttpVersion API — stable across 12.0.x
        return HttpVersion.HTTP_1_1;
    }
}
