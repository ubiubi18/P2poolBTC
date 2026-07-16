import {
  GOV_CRITICAL_MIN_AI_ATTESTATIONS,
  GOV_CRITICAL_MIN_AVAILABILITY_PROVIDERS,
  GOV_CRITICAL_MIN_BUILDERS,
} from "./generated_parameters";
import { Proposal } from "./state";

// The initial contract cannot objectively verify model-family or platform labels.
// A migration remains possible only through stronger, identity-authenticated owner
// breadth while critical and consensus changes stay blocked.
export function bootstrapMigrationAttestationsPass(proposal: Proposal): bool {
  return proposal.risk == "migration"
    && proposal.agentLeafCount > 0
    && proposal.agentSubmittedCount == proposal.agentLeafCount
    && proposal.buildLeafCount > 0
    && proposal.buildSubmittedCount == proposal.buildLeafCount
    && proposal.availabilityLeafCount > 0
    && proposal.availabilitySubmittedCount == proposal.availabilityLeafCount
    && proposal.agentCount >= GOV_CRITICAL_MIN_AI_ATTESTATIONS
    && proposal.agentOwnerCount >= GOV_CRITICAL_MIN_AI_ATTESTATIONS
    && proposal.unresolvedCriticalCount == 0
    && proposal.waiverCid.length == 0
    && proposal.builderOwnerCount >= GOV_CRITICAL_MIN_BUILDERS
    && proposal.builderConflictCount == 0
    && proposal.artifactDigest.length == 64
    && proposal.availabilityOwnerCount >= GOV_CRITICAL_MIN_AVAILABILITY_PROVIDERS;
}
