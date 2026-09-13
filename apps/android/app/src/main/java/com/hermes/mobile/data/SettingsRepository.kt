package com.hermes.mobile.data

import com.hermes.mobile.contract.BotId
import com.hermes.mobile.network.HermesApiClient
import com.hermes.mobile.network.IdempotencyKeys
import com.hermes.mobile.network.SettingsResponse
import com.hermes.mobile.network.SettingsUpdateRequest
import com.hermes.mobile.network.SensitiveSettingsUpdateRequest
import com.hermes.mobile.network.StepUpChallengeResponse
import com.hermes.mobile.security.StepUpProofFactory
import javax.inject.Inject
import javax.inject.Singleton
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject

data class LoadedSettings(
    val bot: BotId,
    val response: SettingsResponse,
    val fetchedAtEpochMillis: Long,
)

/**
 * Profile-scoped host settings operations.
 *
 * Mutations persist the exact encrypted request body before calling OkHttp. A failed request or a
 * 409 revision conflict deliberately leaves the idempotency row in place; the UI must ask the
 * user to review the freshly fetched ETag and explicitly retry instead of replaying mutations on
 * process restart.
 */
@Singleton
class SettingsRepository @Inject constructor(
    private val api: HermesApiClient,
    private val authSession: HermesAuthSession,
    private val idempotency: IdempotencyStore,
    private val stepUpProofs: StepUpProofFactory,
) {
    suspend fun load(bot: BotId, nowEpochMillis: Long): LoadedSettings {
        require(nowEpochMillis >= 0)
        return LoadedSettings(
            bot = bot,
            response = api.getSettings(bot.opaqueProfileId),
            fetchedAtEpochMillis = nowEpochMillis,
        )
    }

    suspend fun createSensitiveChallenge(
        bot: BotId,
        current: SettingsResponse,
        changes: JsonObject,
    ): StepUpChallengeResponse {
        validateCurrent(bot, current)
        SettingsChangePolicy.requireSensitive(changes)
        return api.createSettingsStepUpChallenge(
            opaqueProfileId = bot.opaqueProfileId,
            changes = changes,
        )
    }

    suspend fun updateSafe(
        bot: BotId,
        current: SettingsResponse,
        changes: JsonObject,
        nowEpochMillis: Long,
    ): SettingsResponse {
        validateMutationInputs(bot, current, nowEpochMillis)
        SettingsChangePolicy.requireSafe(changes)
        val request = SettingsUpdateRequest(changes)
        val route = settingsRoute(bot)
        val body = json.encodeToString(request)
        val pending = idempotency.loadLatest(
            bot.instanceId,
            bot.opaqueProfileId,
            SETTINGS_CONVERSATION,
            route,
        )?.takeIf { it.requestBody == body }
        val key = pending?.key ?: IdempotencyKeys.generate()
        if (pending == null) {
            idempotency.persistBeforeAttempt(
                instanceId = bot.instanceId,
                opaqueProfileId = bot.opaqueProfileId,
                conversationId = SETTINGS_CONVERSATION,
                scope = route,
                key = key,
                requestBody = body,
                createdAtEpochMillis = nowEpochMillis,
            )
        }
        val response = api.updateSettings(
            opaqueProfileId = bot.opaqueProfileId,
            request = request,
            ifMatch = current.etag,
            idempotencyKey = key,
        )
        idempotency.delete(
            bot.instanceId,
            bot.opaqueProfileId,
            SETTINGS_CONVERSATION,
            route,
            key,
        )
        return response
    }

    suspend fun updateSensitive(
        bot: BotId,
        current: SettingsResponse,
        changes: JsonObject,
        challenge: StepUpChallengeResponse,
        nowEpochMillis: Long,
    ): SettingsResponse {
        validateMutationInputs(bot, current, nowEpochMillis)
        SettingsChangePolicy.requireSensitive(changes)
        require(challenge.action == "settings.step_up.write") {
            "unexpected settings step-up action"
        }
        val deviceId = requireNotNull(authSession.currentDeviceId()) {
            "approved Hermes device is required for settings step-up"
        }
        val proof = stepUpProofs.create(challenge, deviceId)
        val request = SensitiveSettingsUpdateRequest(changes = changes, stepUp = proof)
        val route = sensitiveSettingsRoute(bot)
        val body = json.encodeToString(request)
        val pending = idempotency.loadLatest(
            bot.instanceId,
            bot.opaqueProfileId,
            SETTINGS_CONVERSATION,
            route,
        )?.takeIf { it.requestBody == body }
        val key = pending?.key ?: IdempotencyKeys.generate()
        if (pending == null) {
            idempotency.persistBeforeAttempt(
                instanceId = bot.instanceId,
                opaqueProfileId = bot.opaqueProfileId,
                conversationId = SETTINGS_CONVERSATION,
                scope = route,
                key = key,
                requestBody = body,
                createdAtEpochMillis = nowEpochMillis,
            )
        }
        val response = api.updateSensitiveSettings(
            opaqueProfileId = bot.opaqueProfileId,
            changes = changes,
            proof = proof,
            ifMatch = current.etag,
            idempotencyKey = key,
        )
        idempotency.delete(
            bot.instanceId,
            bot.opaqueProfileId,
            SETTINGS_CONVERSATION,
            route,
            key,
        )
        return response
    }

    private fun validateMutationInputs(
        bot: BotId,
        current: SettingsResponse,
        nowEpochMillis: Long,
    ) {
        require(nowEpochMillis >= 0)
        validateCurrent(bot, current)
    }

    private fun validateCurrent(bot: BotId, current: SettingsResponse) {
        require(current.profileId == bot.opaqueProfileId) { "settings profile scope mismatch" }
        require(current.revision >= 0) { "settings revision must not be negative" }
        require(current.etag.isNotBlank() && current.etag.length <= MAX_ETAG_LENGTH) {
            "settings ETag is invalid"
        }
        require(current.etag.none { it.isISOControl() }) { "settings ETag contains a control character" }
    }

    private fun settingsRoute(bot: BotId): String =
        "mobile/v1/profiles/${bot.opaqueProfileId}/settings"

    private fun sensitiveSettingsRoute(bot: BotId): String =
        "mobile/v1/profiles/${bot.opaqueProfileId}/settings/sensitive"

    private companion object {
        val json = Json {
            encodeDefaults = true
            explicitNulls = false
        }
        const val SETTINGS_CONVERSATION = "settings"
        const val MAX_ETAG_LENGTH = 256
    }
}
