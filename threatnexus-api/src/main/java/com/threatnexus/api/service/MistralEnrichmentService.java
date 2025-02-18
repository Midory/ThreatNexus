package com.threatnexus.api.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.*;

@Service
public class MistralEnrichmentService {

    @Value("${mistral.api.key}")
    private String mistralApiKey;

    @Value("${mistral.api.url}")
    private String mistralApiUrl;

    @Value("${mistral.agent.id}")
    private String mistralAgentId;

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public MistralEnrichmentService() {
        this.restTemplate = new RestTemplate();
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Calls the Mistral API to enrich CVE details based on the provided prompt.
     *
     * @param cveId            the CVE identifier
     * @param basicDescription a basic description of the vulnerability
     * @return the enriched details as a JSON string
     */
    public String enrichDetails(String cveId, String basicDescription) {
        String prompt = "Provide additional details for " + cveId + " based on the following description: '"
                + basicDescription + "'. Include possible impacts, remediation steps, and any related vulnerabilities.";

        // Build payload for Mistral API.
        Map<String, Object> payload = new HashMap<>();
        payload.put("agent_id", mistralAgentId);
        List<Map<String, String>> messages = new ArrayList<>();
        Map<String, String> message = new HashMap<>();
        message.put("role", "user");
        message.put("content", prompt);
        messages.add(message);
        payload.put("messages", messages);

        // Set up HTTP headers.
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        headers.set("Authorization", "Bearer " + mistralApiKey);

        HttpEntity<Map<String, Object>> requestEntity = new HttpEntity<>(payload, headers);

        // Call the Mistral API.
        ResponseEntity<String> responseEntity = restTemplate.postForEntity(mistralApiUrl, requestEntity, String.class);

        if (responseEntity.getStatusCode().is2xxSuccessful()) {
            return responseEntity.getBody();
        } else {
            throw new RuntimeException("Error calling Mistral API: " + responseEntity.getBody());
        }
    }
}
