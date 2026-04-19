// Copyright (c) 2026 Digital Asset (Switzerland) GmbH and/or its affiliates. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package com.digitalasset.canton.topology.transaction.checks

import com.digitalasset.canton.topology.{ParticipantId, PartyId}
import com.digitalasset.canton.topology.transaction.TemplateBoundPartyMapping
import com.google.protobuf.ByteString
import org.scalatest.matchers.should.Matchers
import org.scalatest.wordspec.AnyWordSpec

class TemplateBoundPartyChecksTest extends AnyWordSpec with Matchers {

  private val partyId = PartyId.tryFromProtoPrimitive("pool::1220abcdef")
  private val participantId = ParticipantId.tryFromProtoPrimitive("PAR::participant1::1220abcdef")
  private val operationalKey = ByteString.copyFrom(Array.fill(32)(0x42.toByte))
  private val newOperationalKey = ByteString.copyFrom(Array.fill(32)(0x99.toByte))
  private val rootKey = ByteString.copyFrom(Array.fill(32)(0xAA.toByte))

  // Trustless mode: no root key, key destruction allowed
  private val trustlessMapping = TemplateBoundPartyMapping(
    partyId = partyId,
    hostingParticipantIds = Seq(participantId),
    allowedTemplateIds = Set("com.example:AMMPool:1.0"),
    signingKeyHash = operationalKey,
    keyDestructionAllowed = true,
    rootKeyHash = ByteString.EMPTY,
  )

  // Regulated mode with root key: key rotation supported
  private val regulatedMapping = TemplateBoundPartyMapping(
    partyId = partyId,
    hostingParticipantIds = Seq(participantId),
    allowedTemplateIds = Set("com.example:AMMPool:1.0"),
    signingKeyHash = operationalKey,
    keyDestructionAllowed = false,
    rootKeyHash = rootKey,
  )

  // Regulated mode without root key: no rotation
  private val simpleRegulatedMapping = TemplateBoundPartyMapping(
    partyId = partyId,
    hostingParticipantIds = Seq(participantId),
    allowedTemplateIds = Set("com.example:AMMPool:1.0"),
    signingKeyHash = operationalKey,
    keyDestructionAllowed = false,
    rootKeyHash = ByteString.EMPTY,
  )

  "TemplateBoundPartyMapping" should {

    "trustless mapping does not support key rotation" in {
      trustlessMapping.supportsKeyRotation shouldBe false
    }

    "regulated mapping with root key supports key rotation" in {
      regulatedMapping.supportsKeyRotation shouldBe true
    }

    "regulated mapping without root key does not support key rotation" in {
      simpleRegulatedMapping.supportsKeyRotation shouldBe false
    }
  }

  "Key rotation validation" should {

    "allow rotating the operational key when root key exists" in {
      val rotated = regulatedMapping.copy(signingKeyHash = newOperationalKey)

      // Only the signing key changed, root key exists
      rotated.signingKeyHash should not be regulatedMapping.signingKeyHash
      rotated.allowedTemplateIds shouldBe regulatedMapping.allowedTemplateIds
      rotated.keyDestructionAllowed shouldBe regulatedMapping.keyDestructionAllowed
      rotated.rootKeyHash shouldBe regulatedMapping.rootKeyHash
      rotated.hostingParticipantIds shouldBe regulatedMapping.hostingParticipantIds
    }

    "reject key rotation when no root key exists (trustless)" in {
      trustlessMapping.supportsKeyRotation shouldBe false
    }

    "reject key rotation when no root key exists (simple regulated)" in {
      simpleRegulatedMapping.supportsKeyRotation shouldBe false
    }

    "reject changing the template whitelist even with root key" in {
      val tampered = regulatedMapping.copy(
        signingKeyHash = newOperationalKey,
        allowedTemplateIds = Set("com.example:AMMPool:1.0", "com.evil:Drain:1.0"),
      )
      // Templates changed, this is NOT a valid key rotation
      tampered.allowedTemplateIds should not be regulatedMapping.allowedTemplateIds
    }

    "reject changing keyDestructionAllowed even with root key" in {
      val tampered = regulatedMapping.copy(
        signingKeyHash = newOperationalKey,
        keyDestructionAllowed = true, // trying to switch to trustless
      )
      tampered.keyDestructionAllowed should not be regulatedMapping.keyDestructionAllowed
    }

    "reject changing the root key itself" in {
      val tampered = regulatedMapping.copy(
        signingKeyHash = newOperationalKey,
        rootKeyHash = ByteString.copyFrom(Array.fill(32)(0xBB.toByte)),
      )
      tampered.rootKeyHash should not be regulatedMapping.rootKeyHash
    }

    "reject changing hosting participants during key rotation" in {
      val participant2 = ParticipantId.tryFromProtoPrimitive("PAR::participant2::1220abcdef")
      val tampered = regulatedMapping.copy(
        signingKeyHash = newOperationalKey,
        hostingParticipantIds = Seq(participantId, participant2),
      )
      tampered.hostingParticipantIds should not be regulatedMapping.hostingParticipantIds
    }

    "reject update that changes nothing (same signing key)" in {
      val sameKey = regulatedMapping.copy()
      sameKey.signingKeyHash shouldBe regulatedMapping.signingKeyHash
      // A no-op update is not a valid key rotation
    }
  }
}
