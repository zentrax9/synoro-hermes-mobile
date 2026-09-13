package com.hermes.mobile.data

import com.hermes.mobile.auth.MobileEnrollmentCoordinator
import com.hermes.mobile.contract.BotId
import com.hermes.mobile.contract.IdempotencyKey
import com.hermes.mobile.contract.OpaqueId
import com.hermes.mobile.network.AttachmentBotId
import com.hermes.mobile.network.GroupCreateRequest
import com.hermes.mobile.network.GroupMemberAddRequest
import com.hermes.mobile.network.GroupMessageRequest
import com.hermes.mobile.network.GroupMessageResponse
import com.hermes.mobile.network.GroupResponse
import com.hermes.mobile.network.HermesApiClient
import com.hermes.mobile.network.HermesAuthExpiredException
import com.hermes.mobile.network.IdempotencyKeys
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * Authenticated group operations used by the presentation layer.
 *
 * Group mutations are persisted before the network attempt, just like direct chat mutations. A
 * failed request intentionally leaves its exact idempotency key/body available for an explicit
 * retry; this repository never retries a group turn implicitly.
 */
@Singleton
class MobileGroupRepository @Inject constructor(
    private val api: HermesApiClient,
    private val authSession: HermesAuthSession,
    private val enrollment: MobileEnrollmentCoordinator,
    private val idempotency: IdempotencyStore,
    private val dao: HermesDao,
) {
    suspend fun createGroup(
        bots: List<BotId>,
        nowEpochMillis: Long,
    ): GroupResponse {
        require(nowEpochMillis >= 0)
        require(bots.size in 2..6) { "a group must contain between 2 and 6 bots" }
        require(bots.distinct().size == bots.size) { "group bots must be unique" }
        require(bots.map { it.instanceId }.distinct().size == 1) {
            "group bots must belong to one Hermes instance"
        }
        val target = bots.first()
        ensureUsableSession(target, nowEpochMillis)
        val request = GroupCreateRequest(
            bots = bots.map { bot -> AttachmentBotId(bot.instanceId, bot.opaqueProfileId) },
        )
        val route = GROUPS_ROUTE
        val body = json.encodeToString(request)
        val response = withMutation(
            target = target,
            conversationId = GROUP_CREATE_CONVERSATION,
            route = route,
            body = body,
            nowEpochMillis = nowEpochMillis,
            validate = { value ->
                validateGroupResponse(value, expectedInstanceId = target.instanceId)
                require(value.members.map { it.bot.toContractBot() }.toSet() == bots.toSet()) {
                    "host returned a different group membership"
                }
                rememberGroup(value, nowEpochMillis)
            },
        ) { key -> api.createGroup(request, key) }
        return response
    }

    suspend fun loadGroup(
        group: GroupResponse,
        nowEpochMillis: Long,
    ): GroupResponse {
        validateGroup(group)
        require(nowEpochMillis >= 0)
        ensureUsableSession(group.members.first().bot.toContractBot(), nowEpochMillis)
        val response = api.getGroup(group.groupId)
        validateGroupResponse(response, group)
        rememberGroup(response, nowEpochMillis)
        return response
    }

    /** Reconcile the durable group snapshot without relying on the local cache as authority. */
    suspend fun listGroups(nowEpochMillis: Long): List<GroupResponse> {
        require(nowEpochMillis >= 0)
        val cached = cachedGroups()
        val sessionTarget = cached.firstOrNull()?.let { reference ->
            BotId(reference.instanceId, reference.anchorProfileId)
        } ?: dao.listSyncTargets().firstOrNull()?.let { target ->
            BotId(target.instanceId, target.opaqueProfileId)
        }
        sessionTarget?.let { target -> ensureUsableSession(target, nowEpochMillis) }
        if (authSession.current() == null) throw HermesAuthExpiredException()
        val allGroups = mutableListOf<GroupResponse>()
        var cursor: String? = null
        var hasMore: Boolean
        do {
            val response = api.listGroups(cursor)
            allGroups += response.groups
            require(allGroups.size <= MAX_GROUP_SNAPSHOT_SIZE) {
                "host returned too many groups in one snapshot"
            }
            hasMore = response.hasMore
            val nextCursor = response.nextCursor
            require(!hasMore || !nextCursor.isNullOrBlank()) {
                "host returned an incomplete group snapshot without a cursor"
            }
            require(!hasMore || nextCursor != cursor) {
                "host returned a repeated group snapshot cursor"
            }
            cursor = nextCursor
        } while (hasMore)
        val responseInstanceIds = allGroups.map { it.instanceId }.distinct()
        require(responseInstanceIds.size <= 1) {
            "host returned groups from multiple Hermes instances"
        }
        allGroups.forEach { group ->
            validateGroupResponse(group, expectedInstanceId = sessionTarget?.instanceId)
            rememberGroup(group, nowEpochMillis)
        }
        // Every page was fetched and cursor-validated, so this is now a complete server-owned
        // snapshot.  Only then is it safe to remove local references absent from the result.
        val returnedIds = allGroups.map { it.groupId }.toSet()
        cached.filter { it.groupId !in returnedIds }.forEach { stale ->
            dao.deleteGroupCache(stale.instanceId, stale.groupId)
        }
        return allGroups
    }

    suspend fun stopGroup(
        group: GroupResponse,
        nowEpochMillis: Long,
    ): GroupResponse {
        validateActiveGroup(group)
        require(nowEpochMillis >= 0)
        val target = group.members.first().bot.toContractBot()
        ensureUsableSession(target, nowEpochMillis)
        val route = groupRoute(group.groupId, "/stop")
        val response = withMutation(
            target = target,
            conversationId = group.groupId,
            route = route,
            body = EMPTY_JSON,
            nowEpochMillis = nowEpochMillis,
            validate = { value ->
                validateGroupResponse(value, group)
                require(value.state == "stopped") { "host did not stop the group" }
                rememberGroup(value, nowEpochMillis)
            },
        ) { key -> api.stopGroup(group.groupId, key) }
        return response
    }

    suspend fun addMember(
        group: GroupResponse,
        bot: BotId,
        nowEpochMillis: Long,
    ): GroupResponse {
        validateActiveGroup(group)
        require(nowEpochMillis >= 0)
        require(bot.instanceId == group.instanceId) {
            "group members must belong to one Hermes instance"
        }
        require(group.members.size < 6) { "a group cannot contain more than 6 bots" }
        require(
            group.members.none { member ->
                member.bot.instanceId == bot.instanceId && member.bot.opaqueProfileId == bot.opaqueProfileId
            },
        ) {
            "bot is already a group member"
        }
        val target = group.members.first().bot.toContractBot()
        ensureUsableSession(target, nowEpochMillis)
        val request = GroupMemberAddRequest(AttachmentBotId(bot.instanceId, bot.opaqueProfileId))
        // The revision is part of the idempotency scope because the server binds
        // If-Match into its mutation digest. The JSON body remains exactly the
        // body sent on the wire; a stale revision must never be replayed silently.
        val route = groupRoute(group.groupId, "/members") + "?revision=${group.authorityEpoch}"
        val body = json.encodeToString(request)
        val response = withMutation(
            target = target,
            conversationId = group.groupId,
            route = route,
            body = body,
            nowEpochMillis = nowEpochMillis,
            validate = { value ->
                validateGroupResponse(value, group)
                rememberGroup(value, nowEpochMillis)
            },
        ) { key -> api.addGroupMember(group.groupId, request, revision(group.authorityEpoch), key) }
        return response
    }

    suspend fun removeMember(
        group: GroupResponse,
        memberId: String,
        nowEpochMillis: Long,
    ): GroupResponse {
        validateActiveGroup(group)
        require(nowEpochMillis >= 0)
        OpaqueId.require(memberId, "memberId")
        require(group.members.size > 2) { "a group must retain at least 2 bots" }
        require(group.members.any { it.memberId == memberId }) {
            "member is not part of this group"
        }
        val target = group.members.first().bot.toContractBot()
        ensureUsableSession(target, nowEpochMillis)
        val route = groupRoute(group.groupId, "/members/$memberId") + "?revision=${group.authorityEpoch}"
        val response = withMutation(
            target = target,
            conversationId = group.groupId,
            route = route,
            body = EMPTY_BODY,
            nowEpochMillis = nowEpochMillis,
            validate = { value ->
                validateGroupResponse(value, group)
                rememberGroup(value, nowEpochMillis)
            },
        ) { key -> api.removeGroupMember(group.groupId, memberId, revision(group.authorityEpoch), key) }
        return response
    }

    suspend fun sendMessage(
        group: GroupResponse,
        text: String,
        mentionedMemberIds: List<String> = emptyList(),
        nowEpochMillis: Long,
    ): GroupMessageResponse {
        validateActiveGroup(group)
        require(nowEpochMillis >= 0)
        require(text.isNotBlank() && text.length <= MAX_GROUP_MESSAGE_LENGTH) {
            "group message text is invalid"
        }
        require(mentionedMemberIds.size <= MAX_GROUP_MEMBERS) {
            "too many mentioned group members"
        }
        mentionedMemberIds.forEach { memberId -> OpaqueId.require(memberId, "mentionedMemberId") }
        require(mentionedMemberIds.distinct().size == mentionedMemberIds.size) {
            "mentioned member IDs must be unique"
        }
        require(mentionedMemberIds.all { memberId -> group.members.any { it.memberId == memberId } }) {
            "group mentions must refer to members"
        }
        val target = group.members.first().bot.toContractBot()
        ensureUsableSession(target, nowEpochMillis)
        val request = GroupMessageRequest(text = text, mentionedMemberIds = mentionedMemberIds)
        val route = groupRoute(group.groupId, "/messages")
        val body = json.encodeToString(request)
        val response = withMutation(
            target = target,
            conversationId = group.groupId,
            route = route,
            body = body,
            nowEpochMillis = nowEpochMillis,
            validate = { value -> validateGroupMessageResponse(value, group) },
        ) { key -> api.sendGroupMessage(group.groupId, request, key) }
        return response
    }

    private suspend fun <T> withMutation(
        target: BotId,
        conversationId: String,
        route: String,
        body: String,
        nowEpochMillis: Long,
        validate: suspend (T) -> Unit = {},
        mutation: suspend (IdempotencyKey) -> T,
    ): T {
        val pending = idempotency.loadLatest(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            conversationId = conversationId,
            scope = route,
        )?.takeIf { it.requestBody == body }
        val key = pending?.key ?: IdempotencyKeys.generate()
        if (pending == null) {
            idempotency.persistBeforeAttempt(
                instanceId = target.instanceId,
                opaqueProfileId = target.opaqueProfileId,
                conversationId = conversationId,
                scope = route,
                key = key,
                requestBody = body,
                createdAtEpochMillis = nowEpochMillis,
            )
        }
        val result = mutation(key)
        // Keep the exact request material until the decoded response has passed
        // all semantic validation. A process death or malformed host response
        // must leave an explicit retry key rather than risking a duplicate.
        validate(result)
        idempotency.delete(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            conversationId = conversationId,
            scope = route,
            key = key,
        )
        return result
    }

    private suspend fun ensureUsableSession(target: BotId, nowEpochMillis: Long) {
        if (authSession.current() == null) {
            if (!authSession.restore(target.instanceId, target.opaqueProfileId)) {
                throw HermesAuthExpiredException()
            }
        }
        val material = authSession.current() ?: throw HermesAuthExpiredException()
        val nowSeconds = nowEpochMillis / 1_000
        if (material.hermesDeviceToken.isUsable(nowSeconds)) return
        val deviceId = authSession.currentDeviceId() ?: throw HermesAuthExpiredException()
        enrollment.refreshApprovedSession(
            instanceId = target.instanceId,
            opaqueProfileId = target.opaqueProfileId,
            cloudflareAccessToken = material.cloudflareAccessToken,
            deviceId = deviceId,
            nowEpochMillis = nowEpochMillis,
        )
    }

    private fun validateGroup(group: GroupResponse) {
        OpaqueId.require(group.groupId, "groupId")
        require(group.members.isNotEmpty()) { "group has no members" }
        require(group.members.size in 2..MAX_GROUP_MEMBERS) {
            "group must contain between two and six members"
        }
        require(group.members.all { member -> member.bot.instanceId == group.instanceId }) {
            "group members must belong to the group instance"
        }
        require(group.instanceId == group.members.first().bot.instanceId) {
            "group instance does not match its members"
        }
        require(group.members.map { it.memberId }.distinct().size == group.members.size) {
            "group member IDs must be unique"
        }
        require(group.members.map { it.bot }.distinct().size == group.members.size) {
            "group bot identities must be unique"
        }
        require(group.members.map { it.ordinal }.distinct().size == group.members.size) {
            "group member ordinals must be unique"
        }
        require(group.members.map { it.ordinal }.sorted() == (0 until group.members.size).toList()) {
            "group member ordinals must be contiguous"
        }
        group.members.forEach { member -> OpaqueId.require(member.memberId, "memberId") }
        OpaqueId.require(group.coordinatorMemberId, "coordinatorMemberId")
        require(group.members.any { member -> member.memberId == group.coordinatorMemberId }) {
            "group coordinator must be a member"
        }
        require(group.state == "active" || group.state == "stopped") {
            "unsupported group state"
        }
        require(group.authorityEpoch >= 1) { "group authority epoch is invalid" }
        group.activeTurnId?.let { turnId -> OpaqueId.require(turnId, "activeTurnId") }
    }

    private fun validateActiveGroup(group: GroupResponse) {
        validateGroup(group)
        require(group.state == "active") { "group is not active" }
    }

    private fun validateGroupResponse(
        response: GroupResponse,
        expected: GroupResponse? = null,
        expectedInstanceId: String? = null,
    ) {
        validateGroup(response)
        expected?.let { previous ->
            require(response.groupId == previous.groupId) { "host returned a different group" }
            require(response.instanceId == previous.instanceId) { "host returned a different instance" }
            require(response.authorityEpoch >= previous.authorityEpoch) {
                "host regressed the group authority epoch"
            }
        }
        expectedInstanceId?.let { instanceId ->
            require(response.instanceId == instanceId) { "host returned a different instance" }
        }
    }

    private fun validateGroupMessageResponse(response: GroupMessageResponse, group: GroupResponse) {
        OpaqueId.require(response.runId, "runId")
        require(response.state in setOf("completed", "cancelled", "indeterminate")) {
            "unsupported group run state"
        }
        require(response.responses.size <= 10) { "group response count exceeds the host limit" }
        require(response.responses.map { it.memberId }.distinct().size == response.responses.size) {
            "group response member IDs must be unique"
        }
        require(response.responses.all { value -> group.members.any { it.memberId == value.memberId } }) {
            "group response member is not in this group"
        }
    }

    private suspend fun rememberGroup(response: GroupResponse, nowEpochMillis: Long) {
        require(nowEpochMillis >= 0)
        validateGroup(response)
        val anchor = response.members.first().bot
        dao.saveGroupCache(
            GroupCacheEntity(
                instanceId = response.instanceId,
                groupId = response.groupId,
                anchorProfileId = anchor.opaqueProfileId,
                updatedAtEpochMillis = nowEpochMillis,
            ),
        )
    }

    suspend fun cachedGroups(): List<CachedGroupReference> =
        dao.listGroupCaches().map { row ->
            OpaqueId.require(row.instanceId, "instanceId")
            OpaqueId.require(row.groupId, "groupId")
            OpaqueId.require(row.anchorProfileId, "anchorProfileId")
            require(row.updatedAtEpochMillis >= 0) { "cached group timestamp is invalid" }
            CachedGroupReference(
                instanceId = row.instanceId,
                groupId = row.groupId,
                anchorProfileId = row.anchorProfileId,
                updatedAtEpochMillis = row.updatedAtEpochMillis,
            )
        }

    suspend fun loadCachedGroup(
        reference: CachedGroupReference,
        nowEpochMillis: Long,
    ): GroupResponse {
        OpaqueId.require(reference.instanceId, "instanceId")
        OpaqueId.require(reference.groupId, "groupId")
        OpaqueId.require(reference.anchorProfileId, "anchorProfileId")
        require(nowEpochMillis >= 0)
        val target = BotId(reference.instanceId, reference.anchorProfileId)
        ensureUsableSession(target, nowEpochMillis)
        val response = api.getGroup(reference.groupId)
        validateGroupResponse(response, expectedInstanceId = reference.instanceId)
        require(response.groupId == reference.groupId) { "host returned a different group" }
        rememberGroup(response, nowEpochMillis)
        return response
    }

    suspend fun forgetGroup(group: GroupResponse) {
        validateGroup(group)
        dao.deleteGroupCache(group.instanceId, group.groupId)
    }

    private fun revision(authorityEpoch: Long): String = "\"group-$authorityEpoch\""

    private fun groupRoute(groupId: String, suffix: String): String {
        OpaqueId.require(groupId, "groupId")
        return "${GROUPS_ROUTE}/$groupId$suffix"
    }

    private fun AttachmentBotId.toContractBot(): BotId = BotId(instanceId, opaqueProfileId)

    private companion object {
        const val GROUPS_ROUTE = "mobile/v1/groups"
        const val GROUP_CREATE_CONVERSATION = "group-create"
        const val EMPTY_BODY = ""
        const val EMPTY_JSON = "{}"
        const val MAX_GROUP_MEMBERS = 6
        const val MAX_GROUP_MESSAGE_LENGTH = 200_000
        const val MAX_GROUP_SNAPSHOT_SIZE = 10_000
        val json = Json { explicitNulls = false }
    }
}

data class CachedGroupReference(
    val instanceId: String,
    val groupId: String,
    val anchorProfileId: String,
    val updatedAtEpochMillis: Long,
)
