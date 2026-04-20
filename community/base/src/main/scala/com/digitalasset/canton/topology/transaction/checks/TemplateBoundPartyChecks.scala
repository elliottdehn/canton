// Copyright (c) 2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package com.digitalasset.canton.topology.transaction.checks

import cats.data.EitherT
import com.digitalasset.canton.lifecycle.FutureUnlessShutdown
import com.digitalasset.canton.topology.processing.EffectiveTime
import com.digitalasset.canton.topology.store.TopologyTransactionRejection
import com.digitalasset.canton.topology.transaction.SignedTopologyTransaction.GenericSignedTopologyTransaction
import com.digitalasset.canton.topology.transaction.TemplateBoundPartyMapping
import com.digitalasset.canton.tracing.TraceContext

import scala.concurrent.ExecutionContext

/** Enforces immutability of template-bound party configurations, with one
  * exception: operational key rotation is allowed when a root key exists.
  *
  * Immutable fields (cannot change after creation):
  *   - allowedTemplateIds (the template whitelist)
  *   - keyDestructionAllowed (trustless vs regulated mode)
  *   - rootKeyHash (the cold storage key itself)
  *   (hosting is managed by PartyToParticipant, not TBP)
  *
  * Mutable field (only when rootKeyHash is set):
  *   - signingKeyHash (operational key rotation)
  *
  * Key rotation flow:
  *   1. Operator detects compromised operational key
  *   2. Pulls root key from cold storage
  *   3. Signs a topology transaction updating signingKeyHash
  *   4. Root key goes back to cold storage
  *   5. Old operational key is revoked
  */
class TemplateBoundPartyChecks(implicit ec: ExecutionContext) extends TopologyMappingChecks {

  override def checkTransaction(
      effective: EffectiveTime,
      toValidate: GenericSignedTopologyTransaction,
      inStore: Option[GenericSignedTopologyTransaction],
      relaxChecksForBackwardsCompatibility: Boolean,
  )(implicit
      traceContext: TraceContext
  ): EitherT[FutureUnlessShutdown, TopologyTransactionRejection, Unit] = {
    (toValidate.mapping, inStore.map(_.mapping)) match {
      case (newMapping: TemplateBoundPartyMapping, Some(existing: TemplateBoundPartyMapping)) =>
        // Update to existing mapping. Check what changed.
        if (isValidKeyRotation(existing, newMapping)) {
          // Only the signing key changed, and the mapping has a root key.
          // This is a valid key rotation.
          EitherT.rightT[FutureUnlessShutdown, TopologyTransactionRejection](())
        } else {
          // Something other than the signing key changed, or no root key exists.
          EitherT.leftT[FutureUnlessShutdown, Unit](
            TopologyTransactionRejection.RequiredMapping.InvalidTopologyMapping(
              "Template-bound party configurations are immutable. " +
                "Only operational key rotation is allowed (requires root key). " +
                "The template whitelist, mode, and root key cannot be modified."
            )
          )
        }

      case (_: TemplateBoundPartyMapping, None) =>
        // First registration — allow it.
        EitherT.rightT[FutureUnlessShutdown, TopologyTransactionRejection](())

      case _ =>
        // Not a TemplateBoundPartyMapping — pass through.
        EitherT.rightT[FutureUnlessShutdown, TopologyTransactionRejection](())
    }
  }

  /** A valid key rotation changes ONLY the signingKeyHash and requires
    * a non-empty rootKeyHash on the existing mapping.
    */
  private def isValidKeyRotation(
      existing: TemplateBoundPartyMapping,
      updated: TemplateBoundPartyMapping,
  ): Boolean =
    existing.supportsKeyRotation &&
      existing.allowedTemplateIds == updated.allowedTemplateIds &&
      existing.keyDestructionAllowed == updated.keyDestructionAllowed &&
      existing.rootKeyHash == updated.rootKeyHash &&
      existing.signingKeyHash != updated.signingKeyHash
}
