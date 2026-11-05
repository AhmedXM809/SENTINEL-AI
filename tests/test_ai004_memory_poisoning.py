import hashlib
import unittest
from dataclasses import replace

from app.core.ai004_memory_poisoning import (
    BENIGN_MEMORY_ENTRY,
    POISONED_MEMORY_ENTRY,
    SCENARIO_ID,
    SCENARIO_MEMORY_ENTRIES,
    SYNTHETIC_MEMORY_CANARY,
    TAMPERED_MEMORY_ENTRY,
    DeterministicMemoryAgent,
    MemoryEntry,
    inspect_memory_entry,
    run_ai_004,
)


class AI004MemoryPoisoningTests(unittest.TestCase):

    def test_scenario_identity_and_fixed_entry_count(self):
        self.assertEqual(SCENARIO_ID, "AI-004")
        self.assertEqual(len(SCENARIO_MEMORY_ENTRIES), 3)

    def test_trusted_benign_memory_passes_inspection(self):
        result = inspect_memory_entry(BENIGN_MEMORY_ENTRY)

        self.assertTrue(result.integrity_valid)
        self.assertTrue(result.provenance_valid)
        self.assertTrue(result.attestation_valid)
        self.assertFalse(result.injection_detected)
        self.assertEqual(result.detection_rule_ids, ())

    def test_poisoned_memory_detects_persistent_instructions(self):
        result = inspect_memory_entry(POISONED_MEMORY_ENTRY)

        self.assertTrue(result.integrity_valid)
        self.assertFalse(result.provenance_valid)
        self.assertTrue(result.attestation_valid)
        self.assertTrue(result.injection_detected)

        expected_rules = {
            "MEM-OVERRIDE-001",
            "MEM-PERSISTENCE-001",
            "MEM-ROLE-ESCALATION-001",
            "MEM-CANARY-EXFILTRATION-001",
            "MEM-PROVENANCE-001",
        }

        self.assertTrue(
            expected_rules.issubset(set(result.detection_rule_ids))
        )

    def test_tampered_memory_fails_integrity_verification(self):
        result = inspect_memory_entry(TAMPERED_MEMORY_ENTRY)

        self.assertFalse(result.integrity_valid)
        self.assertTrue(result.provenance_valid)
        self.assertTrue(result.attestation_valid)
        self.assertTrue(result.injection_detected)
        self.assertIn(
            "MEM-INTEGRITY-001",
            result.detection_rule_ids,
        )

    def test_source_identifier_spoof_cannot_reuse_attestation(self):
        spoofed = replace(BENIGN_MEMORY_ENTRY, source_id='external_note_import')
        inspection = inspect_memory_entry(spoofed)
        self.assertFalse(inspection.provenance_valid)
        self.assertFalse(inspection.attestation_valid)
        agent = DeterministicMemoryAgent('secure')
        decision = agent.ingest(spoofed)
        self.assertFalse(decision.stored)
        self.assertTrue(decision.quarantined)
        self.assertIn('MEM-ATTESTATION-001', decision.detection_rule_ids)

    def test_recomputed_digest_without_new_attestation_is_rejected(self):
        content = POISONED_MEMORY_ENTRY.content
        digest = hashlib.sha256(content.encode('utf-8')).hexdigest()
        forged = replace(BENIGN_MEMORY_ENTRY, content=content, content_sha256=digest)
        inspection = inspect_memory_entry(forged)
        self.assertTrue(inspection.integrity_valid)
        self.assertTrue(inspection.provenance_valid)
        self.assertFalse(inspection.attestation_valid)
        agent = DeterministicMemoryAgent('secure')
        decision = agent.ingest(forged)
        self.assertFalse(decision.stored)
        self.assertTrue(decision.quarantined)

    def test_modified_attestation_is_rejected(self):
        forged = replace(BENIGN_MEMORY_ENTRY, source_attestation='0' * 64)
        inspection = inspect_memory_entry(forged)
        self.assertFalse(inspection.attestation_valid)
        self.assertIn('MEM-ATTESTATION-001', inspection.detection_rule_ids)
    def test_secure_agent_preserves_benign_memory(self):
        agent = DeterministicMemoryAgent("secure")

        decision = agent.ingest(BENIGN_MEMORY_ENTRY)

        self.assertTrue(decision.stored)
        self.assertFalse(decision.quarantined)
        self.assertEqual(decision.decision, "STORED_VERIFIED")

        retrieved = agent.retrieve(BENIGN_MEMORY_ENTRY.memory_id)

        self.assertTrue(retrieved.retrieved)
        self.assertFalse(retrieved.instruction_applied)
        self.assertFalse(retrieved.synthetic_canary_exposed)
        self.assertEqual(
            retrieved.decision,
            "RETRIEVED_AS_TRUSTED_DATA",
        )

    def test_secure_agent_quarantines_poisoned_memory(self):
        agent = DeterministicMemoryAgent("secure")

        decision = agent.ingest(POISONED_MEMORY_ENTRY)

        self.assertFalse(decision.stored)
        self.assertTrue(decision.quarantined)
        self.assertEqual(decision.decision, "QUARANTINED")

    def test_secure_agent_quarantines_tampered_memory(self):
        agent = DeterministicMemoryAgent("secure")

        decision = agent.ingest(TAMPERED_MEMORY_ENTRY)

        self.assertFalse(decision.stored)
        self.assertTrue(decision.quarantined)
        self.assertFalse(decision.integrity_valid)

    def test_quarantined_memory_is_excluded_from_retrieval(self):
        agent = DeterministicMemoryAgent("secure")

        agent.ingest(POISONED_MEMORY_ENTRY)
        result = agent.retrieve(POISONED_MEMORY_ENTRY.memory_id)

        self.assertFalse(result.retrieved)
        self.assertFalse(result.instruction_applied)
        self.assertFalse(result.synthetic_canary_exposed)
        self.assertEqual(result.decision, "BLOCKED_QUARANTINED")
        self.assertNotIn(SYNTHETIC_MEMORY_CANARY, result.synthetic_response)

    def test_vulnerable_agent_follows_poisoned_memory_later(self):
        agent = DeterministicMemoryAgent("vulnerable")

        ingestion = agent.ingest(POISONED_MEMORY_ENTRY)
        retrieval = agent.retrieve(POISONED_MEMORY_ENTRY.memory_id)

        self.assertTrue(ingestion.stored)
        self.assertFalse(ingestion.quarantined)
        self.assertTrue(retrieval.retrieved)
        self.assertTrue(retrieval.instruction_applied)
        self.assertTrue(retrieval.synthetic_canary_exposed)
        self.assertIn(SYNTHETIC_MEMORY_CANARY, retrieval.synthetic_response)

    def test_vulnerable_agent_accepts_tampered_memory(self):
        agent = DeterministicMemoryAgent("vulnerable")

        decision = agent.ingest(TAMPERED_MEMORY_ENTRY)

        self.assertTrue(decision.stored)
        self.assertFalse(decision.quarantined)

        retrieved = agent.retrieve(TAMPERED_MEMORY_ENTRY.memory_id)

        self.assertTrue(retrieved.instruction_applied)
        self.assertTrue(retrieved.synthetic_canary_exposed)

    def test_secure_agent_revalidates_memory_during_retrieval(self):
        agent = DeterministicMemoryAgent("secure")

        original = BENIGN_MEMORY_ENTRY
        agent.ingest(original)

        # Test-only simulation of an attacker changing the stored record
        # between ingestion and the later retrieval interaction.
        tampered = replace(
            original,
            content=POISONED_MEMORY_ENTRY.content,
        )

        agent._active[original.memory_id] = tampered

        result = agent.retrieve(original.memory_id)

        self.assertFalse(result.retrieved)
        self.assertFalse(result.instruction_applied)
        self.assertFalse(result.synthetic_canary_exposed)
        self.assertEqual(result.decision, "BLOCKED_REVALIDATION")
        self.assertEqual(agent.quarantined_count, 1)
        self.assertEqual(agent.stored_count, 0)
        self.assertIn(
            "MEM-INTEGRITY-001",
            result.detection_rule_ids,
        )

    def test_duplicate_memory_identifiers_are_rejected(self):
        agent = DeterministicMemoryAgent("secure")

        agent.ingest(BENIGN_MEMORY_ENTRY)

        with self.assertRaises(ValueError):
            agent.ingest(BENIGN_MEMORY_ENTRY)

    def test_missing_memory_returns_safe_result(self):
        agent = DeterministicMemoryAgent("secure")

        result = agent.retrieve("UNKNOWN-MEMORY")

        self.assertFalse(result.retrieved)
        self.assertFalse(result.instruction_applied)
        self.assertFalse(result.synthetic_canary_exposed)
        self.assertEqual(result.decision, "MEMORY_NOT_FOUND")

    def test_invalid_memory_entry_and_digest_are_rejected(self):
        with self.assertRaises(TypeError):
            inspect_memory_entry(None)

        invalid_digest = replace(
            BENIGN_MEMORY_ENTRY,
            content_sha256="invalid",
        )

        with self.assertRaises(ValueError):
            inspect_memory_entry(invalid_digest)

    def test_unsupported_target_is_rejected(self):
        with self.assertRaises(ValueError):
            DeterministicMemoryAgent("production")

    def test_full_ai004_simulation_passes(self):
        result = run_ai_004()

        self.assertEqual(result["scenario_id"], "AI-004")
        self.assertEqual(result["evaluation"]["blue_team_control"], "PASS")
        self.assertEqual(result["interaction_count"], 2)
        self.assertTrue(result["simulation_only"])
        self.assertFalse(result["persisted"])

        evaluation = result["evaluation"]

        self.assertTrue(evaluation["persistent_instruction_detected"])
        self.assertTrue(evaluation["untrusted_provenance_detected"])
        self.assertTrue(evaluation["benign_source_attestation_valid"])
        self.assertTrue(evaluation["untrusted_source_attestation_valid"])
        self.assertTrue(evaluation["tampered_memory_detected"])
        self.assertTrue(evaluation["trusted_benign_memory_preserved"])
        self.assertTrue(evaluation["poisoned_memory_quarantined"])
        self.assertTrue(evaluation["tampered_memory_quarantined"])

        self.assertTrue(
            evaluation["vulnerable_agent_followed_persistent_instruction"]
        )
        self.assertFalse(
            evaluation["secure_agent_followed_persistent_instruction"]
        )
        self.assertTrue(evaluation["vulnerable_agent_disclosed_canary"])
        self.assertFalse(evaluation["secure_agent_disclosed_canary"])

    def test_simulation_is_deterministic(self):
        self.assertEqual(run_ai_004(), run_ai_004())

    def test_no_real_memory_or_external_side_effects(self):
        result = run_ai_004()

        self.assertEqual(result["memory_storage"], "ephemeral_in_memory")
        self.assertFalse(result["persisted"])
        self.assertFalse(result["real_memory_accessed"])
        self.assertFalse(result["real_filesystem_accessed"])
        self.assertFalse(result["real_network_requests_sent"])
        self.assertFalse(result["real_accounts_modified"])
        self.assertFalse(result["external_provider_used"])

    def test_raw_memory_content_is_not_returned(self):
        result = run_ai_004()

        self.assertFalse(result["raw_memory_content_returned"])

        serialized = str(result)

        for entry in SCENARIO_MEMORY_ENTRIES:
            self.assertNotIn(entry.content, serialized)


if __name__ == "__main__":
    unittest.main(verbosity=2)
