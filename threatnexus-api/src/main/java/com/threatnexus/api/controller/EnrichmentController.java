package com.threatnexus.api.controller;


import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.threatnexus.api.model.Vulnerability;
import com.threatnexus.api.repository.VulnerabilityRepository;
import com.threatnexus.api.service.MistralEnrichmentService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Optional;

@RestController
@CrossOrigin(origins = "http://localhost:3000")
@RequestMapping("/api/enrich")
public class EnrichmentController {

    private final VulnerabilityRepository vulnerabilityRepository;
    private final MistralEnrichmentService mistralEnrichmentService;
    private final ObjectMapper objectMapper;

    public EnrichmentController(VulnerabilityRepository vulnerabilityRepository,
                                MistralEnrichmentService mistralEnrichmentService) {
        this.vulnerabilityRepository = vulnerabilityRepository;
        this.mistralEnrichmentService = mistralEnrichmentService;
        this.objectMapper = new ObjectMapper();
    }

    @GetMapping("/{cveId}")
    public ResponseEntity<?> enrichCve(@PathVariable String cveId) {
        // Retrieve vulnerability by CVE ID.
        Optional<Vulnerability> optionalVuln = vulnerabilityRepository.findByCveId(cveId);
        if (optionalVuln.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body("Vulnerability with CVE ID " + cveId + " not found.");
        }
        Vulnerability vulnerability = optionalVuln.get();

        // Extract basic description from the JSON data.
        String basicDescription = "";
        try {
            JsonNode root = objectMapper.readTree(vulnerability.getData());
            JsonNode descriptions = root.path("cve").path("descriptions");
            if (descriptions.isArray()) {
                for (JsonNode desc : descriptions) {
                    if ("en".equalsIgnoreCase(desc.path("lang").asText())) {
                        basicDescription = desc.path("value").asText();
                        break;
                    }
                }
            }
        } catch (Exception ex) {
            basicDescription = "No description available.";
        }

        // Call the Mistral API via the dedicated service.
        String enrichedContent;
        try {
            enrichedContent = mistralEnrichmentService.enrichDetails(cveId, basicDescription);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Error calling Mistral API: " + e.getMessage());
        }

        // Save the enriched details into the vulnerability record.
        vulnerability.setEnrichedDetails(enrichedContent);
        vulnerabilityRepository.save(vulnerability);

        return ResponseEntity.ok(enrichedContent);
    }
}