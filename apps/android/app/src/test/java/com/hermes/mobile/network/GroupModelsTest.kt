package com.hermes.mobile.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class GroupModelsTest {
    private val instanceId = "instance-123456"
    private val firstProfile = AttachmentBotId(instanceId, "profile-123456")
    private val secondProfile = AttachmentBotId(instanceId, "profile-234567")
    private val firstMember = GroupMemberWire("member-123456", firstProfile, "Bot one", 0)
    private val secondMember = GroupMemberWire("member-234567", secondProfile, "Bot two", 1)

    @Test
    fun groupCreateRequiresTwoToSixBotsFromOneInstance() {
        assertThrows(IllegalArgumentException::class.java) {
            GroupCreateRequest(listOf(firstProfile))
        }
        assertThrows(IllegalArgumentException::class.java) {
            GroupCreateRequest(
                listOf(firstProfile, AttachmentBotId("instance-234567", "profile-345678")),
            )
        }
        assertEquals(2, GroupCreateRequest(listOf(firstProfile, secondProfile)).bots.size)
    }

    @Test
    fun groupResponseRejectsUnknownStateDuplicateBotsAndCrossInstanceMembers() {
        assertThrows(IllegalArgumentException::class.java) {
            GroupResponse(
                groupId = "group-123456",
                instanceId = instanceId,
                members = listOf(firstMember, secondMember),
                coordinatorMemberId = firstMember.memberId,
                state = "unknown",
                authorityEpoch = 1,
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            GroupResponse(
                groupId = "group-123456",
                instanceId = instanceId,
                members = listOf(secondMember, secondMember.copy(memberId = "member-345678")),
                coordinatorMemberId = secondMember.memberId,
                state = "active",
                authorityEpoch = 1,
            )
        }
        assertThrows(IllegalArgumentException::class.java) {
            GroupResponse(
                groupId = "group-123456",
                instanceId = instanceId,
                members = listOf(
                    firstMember,
                    secondMember.copy(
                        bot = AttachmentBotId("instance-234567", "profile-345678"),
                    ),
                ),
                coordinatorMemberId = firstMember.memberId,
                state = "active",
                authorityEpoch = 1,
            )
        }
    }

    @Test
    fun groupMessageBoundsAndMentionIdsAreValidated() {
        assertThrows(IllegalArgumentException::class.java) {
            GroupMessageRequest(text = " ")
        }
        assertThrows(IllegalArgumentException::class.java) {
            GroupMessageRequest(text = "hello", mentionedMemberIds = listOf("../member"))
        }
        val request = GroupMessageRequest(
            text = "hello",
            mentionedMemberIds = listOf("member-123456"),
        )
        assertEquals("hello", request.text)
        assertThrows(IllegalArgumentException::class.java) {
            GroupMessageResponse(
                runId = "run-123456",
                state = "completed",
                responses = List(11) { GroupBotResponseWire(firstMember.memberId, "reply") },
            )
        }
    }
}
