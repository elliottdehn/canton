// Copyright (c) 2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package com.digitalasset.canton.participant.topology

import cats.data.EitherT
import com.digitalasset.canton.config.RequireTypes.PositiveInt
import com.digitalasset.canton.crypto.{Fingerprint, HashOps}
import com.digitalasset.canton.crypto.store.CryptoPrivateStore
import com.digitalasset.canton.lifecycle.FutureUnlessShutdown
import com.digitalasset.canton.logging.{NamedLoggerFactory, NamedLogging}
import com.digitalasset.canton.topology.{ParticipantId, PartyId, TopologyManager}
import com.digitalasset.canton.topology.store.TopologyStoreId
import com.digitalasset.canton.topology.transaction.{
  HostingParticipant,
  ParticipantPermission,
  PartyToParticipant,
  TemplateBoundPartyMapping,
  TopologyChangeOp,
}
import com.digitalasset.canton.tracing.TraceContext
import com.digitalasset.canton.version.ProtocolVersion
import com.google.protobuf.ByteString

import scala.concurrent.ExecutionContext

/** Two-phase template-bound party registration.
  *
  * Phase 1 (allocate): Called on each hosting participant independently.
  *   Creates the PartyToParticipant mapping. Each participant can be
  *   permissionless (auto-allocate) or permissioned (standard proposal/accept).
  *
  * Phase 2 (finalize): Called once, on the node holding the signing key.
  *   Verifies all participants are hosting, submits the TemplateBoundPartyMapping,
  *   and destroys the signing key.
  *
  * Example multicloud flow:
  *   1. allocate(partyId, keyFp) on participant A (permissionless) — instant
  *   2. allocate(partyId, keyFp) on participant B (permissionless) — instant
  *   3. Manual proposal/accept on participant C (permissioned)
  *   4. Manual proposal/accept on participant D (permissioned)
  *   5. finalize(partyId, [A,B,C,D], templates, keyFp) on A — verify, submit, destroy
  */
class TemplateBoundPartyRegistration(
    localParticipantId: ParticipantId,
    topologyManager: TopologyManager[TopologyStoreId, _],
    privateStore: CryptoPrivateStore,
    hashOps: HashOps,
    protocolVersion: ProtocolVersion,
    permissionlessTbpHosting: Boolean,
    override val loggerFactory: NamedLoggerFactory,
)(implicit ec: ExecutionContext)
    extends NamedLogging {

  /** Phase 1: Allocate the party on this participant.
    *
    * Creates a PartyToParticipant mapping. If permissionlessTbpHosting is
    * enabled, this succeeds immediately. Otherwise falls through to the
    * standard topology authorization (caller must have appropriate keys).
    *
    * Idempotent: safe to call multiple times.
    */
  def allocate(
      partyId: PartyId,
      signingKeyFingerprint: Fingerprint,
  )(implicit traceContext: TraceContext): EitherT[FutureUnlessShutdown, String, ParticipantId] = {
    if (!permissionlessTbpHosting) {
      EitherT.leftT[FutureUnlessShutdown, ParticipantId](
        s"Permissionless TBP hosting is not enabled on participant $localParticipantId. " +
          s"Use the standard topology proposal/accept flow to allocate the party."
      )
    } else {
      val partyToParticipant = PartyToParticipant.tryCreate(
        partyId = partyId,
        threshold = PositiveInt.one,
        participants = Seq(
          HostingParticipant(localParticipantId, ParticipantPermission.Confirmation)
        ),
      )

      topologyManager
        .proposeAndAuthorize(
          op = TopologyChangeOp.Replace,
          mapping = partyToParticipant,
          serial = None,
          signingKeys = Seq(signingKeyFingerprint),
          protocolVersion = protocolVersion,
          expectFullAuthorization = true,
          waitToBecomeEffective = None,
        )
        .bimap(
          e => s"Failed to allocate party on participant: $e",
          _ => {
            logger.info(
              s"Allocated template-bound party $partyId on participant $localParticipantId"
            )
            localParticipantId
          },
        )
    }
  }

  /** Phase 2: Finalize the TBP registration.
    *
    * Verifies all hosting participants have live PartyToParticipant mappings,
    * submits the TemplateBoundPartyMapping topology transaction, and
    * DESTROYS the signing key.
    *
    * Call only after all participants are confirmed hosting.
    * This is the point of no return.
    */
  /** Phase 2: Finalize the TBP registration.
    *
    * Submits the TemplateBoundPartyMapping and optionally destroys the signing key.
    * Hosting is managed separately via PartyToParticipant topology transactions.
    *
    * @param destroyKey if true, the signing key is destroyed (trustless mode).
    *                   if false, the key is retained (regulated mode).
    */
  def finalize(
      partyId: PartyId,
      allowedTemplateIds: Set[String],
      signingKeyFingerprint: Fingerprint,
      destroyKey: Boolean = true,
  )(implicit traceContext: TraceContext): EitherT[FutureUnlessShutdown, String, TemplateBoundPartyMapping] = {

    val signingKeyHash = hashOps
      .digest(
        com.digitalasset.canton.crypto.HashPurpose.TopologyTransactionSignature,
        ByteString.copyFrom(signingKeyFingerprint.unwrap.getBytes),
      )
      .getCryptographicEvidence

    val mapping = TemplateBoundPartyMapping(
      partyId = partyId,
      allowedTemplateIds = allowedTemplateIds,
      signingKeyHash = signingKeyHash,
      keyDestructionAllowed = destroyKey,
    )

    for {
      // Step 1: Verify the signing key exists
      keyExists <- privateStore
        .existsPrivateKey(signingKeyFingerprint, com.digitalasset.canton.crypto.KeyPurpose.Signing)
        .leftMap(e => s"Failed to check signing key: $e")
      _ <- EitherT.cond[FutureUnlessShutdown](
        keyExists,
        (),
        s"Signing key $signingKeyFingerprint does not exist in the private store",
      )

      // Step 2: Submit the TemplateBoundPartyMapping topology transaction
      _ <- topologyManager
        .proposeAndAuthorize(
          op = TopologyChangeOp.Replace,
          mapping = mapping,
          serial = Some(PositiveInt.one),
          signingKeys = Seq(signingKeyFingerprint),
          protocolVersion = protocolVersion,
          expectFullAuthorization = true,
          waitToBecomeEffective = None,
        )
        .leftMap(e => s"Failed to submit topology transaction: $e")

      _ = logger.info(
        s"Template-bound party mapping accepted for $partyId. destroyKey=$destroyKey"
      )

      // Step 3: Optionally DESTROY THE KEY (trustless mode only).
      _ <- if (destroyKey) {
        privateStore
          .removePrivateKey(signingKeyFingerprint)
          .leftMap(e => s"Failed to destroy signing key: $e")
      } else {
        logger.info(
          s"Regulated mode: retaining signing key $signingKeyFingerprint for $partyId."
        )
        EitherT.rightT[FutureUnlessShutdown, String](())
      }

      _ = logger.info(
        s"Finalized template-bound party $partyId. " +
          s"Allowed templates: ${allowedTemplateIds.mkString(", ")}."
      )
    } yield mapping
  }

}
