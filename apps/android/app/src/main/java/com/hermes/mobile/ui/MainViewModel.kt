package com.hermes.mobile.ui

import android.content.Context
import android.net.Uri
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.hermes.mobile.BuildConfig
import com.hermes.mobile.auth.AuthorizationStart
import com.hermes.mobile.auth.MobileEnrollmentCoordinator
import com.hermes.mobile.auth.PendingDeviceEnrollment
import com.hermes.mobile.contract.AttentionState
import com.hermes.mobile.contract.BotId
import com.hermes.mobile.contract.ConversationId
import com.hermes.mobile.contract.MessagePart
import com.hermes.mobile.contract.RunState
import com.hermes.mobile.contract.TransportState
import com.hermes.mobile.data.AppPreferencesRepository
import com.hermes.mobile.data.ApprovalRepository
import com.hermes.mobile.data.AuthenticationCacheInvalidatedException
import com.hermes.mobile.data.AttachmentUploadRepository
import com.hermes.mobile.data.HermesDao
import com.hermes.mobile.data.HermesAuthSession
import com.hermes.mobile.data.MobileChatRepository
import com.hermes.mobile.data.MobileGroupRepository
import com.hermes.mobile.data.MobileOperationInProgressException
import com.hermes.mobile.data.MobileOperationStates
import com.hermes.mobile.data.PendingConversationCreate
import com.hermes.mobile.data.classifyMobileSendFailure
import com.hermes.mobile.data.PushRegistrationCoordinator
import com.hermes.mobile.data.SettingsRepository
import com.hermes.mobile.media.VoiceNoteRecorder
import com.hermes.mobile.media.VoiceNoteCapture
import com.hermes.mobile.network.HermesApiException
import com.hermes.mobile.network.HermesApiClient
import com.hermes.mobile.network.HermesAuthExpiredException
import com.hermes.mobile.network.CursorExpiredException
import com.hermes.mobile.network.ConversationWire
import com.hermes.mobile.network.RunWire
import com.hermes.mobile.network.GroupResponse
import com.hermes.mobile.network.SettingsResponse
import com.hermes.mobile.network.StepUpChallengeResponse
import com.hermes.mobile.security.LocalLockState
import com.hermes.mobile.security.CacheWiper
import com.hermes.mobile.security.UnreadableEncryptedValueException
import dagger.hilt.android.lifecycle.HiltViewModel
import javax.inject.Inject
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.Job
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

private const val MIN_GROUP_MEMBERS = 2
private const val MAX_GROUP_MEMBERS = 6
private const val MAX_GROUP_MESSAGE_LENGTH = 200_000
private const val MAX_DRAFT_LENGTH = 32_000
private const val DRAFT_PERSIST_DEBOUNCE_MILLIS = 250L
private const val EVENT_STREAM_RECONNECT_DELAY_MILLIS = 1_000L

/** Presentation-only state. Server-issued IDs remain the only routing identifiers. */
data class BotCardState(
    val bot: BotId,
    val displayName: String,
    val originLabel: String,
    val runState: RunState = RunState.COMPLETED,
    val transport: TransportState = TransportState.DISCONNECTED,
    val attention: AttentionState = AttentionState.NONE,
)

enum class TranscriptRole { USER, BOT, SYSTEM }

enum class DeliveryState { PENDING, SENT, FAILED }

enum class SendRecoveryAction { NONE, RETRY_ORIGINAL, EDIT_AS_NEW }

/** UI policy is intentionally pure so rejected/conflicted sends cannot accidentally replay. */
fun sendRecoveryAction(operationState: String?): SendRecoveryAction = when {
    operationState == MobileOperationStates.UNCERTAIN -> SendRecoveryAction.RETRY_ORIGINAL
    operationState != null && operationState in MobileOperationStates.EDITABLE_AS_NEW -> SendRecoveryAction.EDIT_AS_NEW
    else -> SendRecoveryAction.NONE
}

enum class ConversationCreateRecoveryAction { NONE, RETRY_ORIGINAL, WAIT }

/** A pending New chat blocks a fresh key; only an uncertain operation may be retried explicitly. */
fun conversationCreateRecoveryAction(
    pending: PendingConversationCreate?,
): ConversationCreateRecoveryAction = when {
    pending == null -> ConversationCreateRecoveryAction.NONE
    pending.state == MobileOperationStates.UNCERTAIN -> ConversationCreateRecoveryAction.RETRY_ORIGINAL
    else -> ConversationCreateRecoveryAction.WAIT
}

data class TranscriptCard(
    val messageId: String,
    val authorLabel: String,
    val role: TranscriptRole,
    val parts: List<MessagePart>,
    val delivery: DeliveryState = DeliveryState.SENT,
    val runState: RunState? = null,
    val operationId: String? = null,
    val operationState: String? = null,
    val runId: String? = null,
)

data class ConversationCardState(
    val conversationId: String,
    val title: String,
    val canonical: Boolean,
    val updatedAtEpochMillis: Long,
    val isStale: Boolean = false,
)

data class DirectRunUiState(
    val runId: String? = null,
    val state: RunState = RunState.COMPLETED,
    val cancelRequested: Boolean = false,
    val completedExternalSideEffectsNotUndone: Boolean = false,
    val isCancelling: Boolean = false,
    val message: String? = null,
)

data class EditAsNewConfirmation(val operationId: String)

data class GroupMemberCard(
    val memberId: String,
    val label: String,
    val bot: BotId,
)

enum class GroupLifecycle { ACTIVE, STOPPED }

data class GroupRunCard(
    val runId: String,
    val state: String,
)

data class GroupUiState(
    val groupId: String? = null,
    val instanceId: String? = null,
    val coordinatorMemberId: String? = null,
    val members: List<GroupMemberCard> = emptyList(),
    val lifecycle: GroupLifecycle? = null,
    val authorityEpoch: Long? = null,
    val activeTurnId: String? = null,
    val selectedBotIds: List<BotId> = emptyList(),
    val draft: String = "",
    val isLoading: Boolean = false,
    val isMutating: Boolean = false,
    val lastRun: GroupRunCard? = null,
    val message: String? = null,
)

data class PendingApprovalCard(
    val approvalId: String,
    val summary: String,
    val expiresAtEpochMillis: Long,
)

enum class HomeSection { CHAT, GROUPS, ROUTINES, SETTINGS }

enum class EnrollmentPhase { IDLE, AUTHORIZING, AWAITING_APPROVAL, CONNECTING, CONNECTED, ERROR }

data class EnrollmentUiState(
    val phase: EnrollmentPhase = EnrollmentPhase.IDLE,
    val deviceLabel: String = "Hermes Android",
    val deviceId: String? = null,
    val enrollmentCode: String? = null,
    val message: String? = null,
)

data class SettingsUiState(
    val isLoading: Boolean = false,
    val isSaving: Boolean = false,
    val profileId: String? = null,
    val revision: Long? = null,
    val displayName: String = "",
    val title: String = "",
    val avatar: String = "",
    val notificationsEnabled: Boolean? = null,
    val persona: String = "",
    val draftDisplayName: String = "",
    val draftTitle: String = "",
    val draftAvatar: String = "",
    val draftNotificationsEnabled: Boolean? = null,
    val draftPersona: String = "",
    val stepUpReady: Boolean = false,
    val message: String? = null,
)

data class MainUiState(
    val bots: List<BotId> = emptyList(),
    val botCards: List<BotCardState> = emptyList(),
    val selectedBot: BotId? = null,
    val selectedConversationId: ConversationId? = null,
    val conversations: List<ConversationCardState> = emptyList(),
    val conversationsStale: Boolean = false,
    val isLoadingConversations: Boolean = false,
    val transcript: List<TranscriptCard> = emptyList(),
    val directRun: DirectRunUiState = DirectRunUiState(),
    val directRuns: List<DirectRunUiState> = emptyList(),
    val pendingConversationCreate: PendingConversationCreate? = null,
    val editAsNewConfirmation: EditAsNewConfirmation? = null,
    val group: GroupUiState = GroupUiState(),
    val pendingApprovals: List<PendingApprovalCard> = emptyList(),
    val section: HomeSection = HomeSection.CHAT,
    val draft: String = "",
    val selectedAttachmentCount: Int = 0,
    val selectedAttachmentIds: List<String> = emptyList(),
    val isAttachmentUploading: Boolean = false,
    val isRecording: Boolean = false,
    val pendingVoiceNoteDurationMillis: Long? = null,
    val composerMessage: String? = null,
    val transport: TransportState = TransportState.DISCONNECTED,
    val attention: AttentionState = AttentionState.NONE,
    val blockScreenshots: Boolean = true,
    val localLockEnabled: Boolean = true,
    val isLocked: Boolean = true,
    val enrollment: EnrollmentUiState = EnrollmentUiState(),
    val settings: SettingsUiState = SettingsUiState(),
)

sealed interface MainIntent {
    data object Refresh : MainIntent
    data class SelectBot(val bot: BotId) : MainIntent
    data class SelectConversation(val conversationId: String) : MainIntent
    data object CreateConversation : MainIntent
    data class SelectSection(val section: HomeSection) : MainIntent
    data class SetDraft(val text: String) : MainIntent
    data object SendDraft : MainIntent
    data class RetrySend(val operationId: String) : MainIntent
    data object RetryCreateConversation : MainIntent
    data class EditAsNewMessage(val operationId: String) : MainIntent
    data object ConfirmEditAsNewMessage : MainIntent
    data object DismissEditAsNewMessage : MainIntent
    data class CancelRun(val runId: String) : MainIntent
    data class RefreshRun(val runId: String) : MainIntent
    data object AddAttachment : MainIntent
    data object ClearAttachments : MainIntent
    data class AttachmentSelected(val uri: Uri) : MainIntent
    data object ToggleVoiceNote : MainIntent
    data object VoicePermissionDenied : MainIntent
    data object SendVoiceNote : MainIntent
    data object DiscardVoiceNote : MainIntent
    data class ToggleGroupBot(val bot: BotId) : MainIntent
    data object CreateGroup : MainIntent
    data object RefreshGroup : MainIntent
    data class AddGroupMember(val bot: BotId) : MainIntent
    data class RemoveGroupMember(val memberId: String) : MainIntent
    data class SetGroupDraft(val text: String) : MainIntent
    data object SendGroupMessage : MainIntent
    data object StopGroup : MainIntent
    data object ClearGroup : MainIntent
    data class SetDeviceLabel(val label: String) : MainIntent
    data object StartEnrollment : MainIntent
    data object CheckEnrollment : MainIntent
    data class SetSettingsDisplayName(val value: String) : MainIntent
    data class SetSettingsTitle(val value: String) : MainIntent
    data class SetSettingsAvatar(val value: String) : MainIntent
    data class SetSettingsNotifications(val enabled: Boolean) : MainIntent
    data class SetSettingsPersona(val value: String) : MainIntent
    data object SaveSettings : MainIntent
    data object PrepareSensitiveSettings : MainIntent
    data object SettingsStepUpAuthenticationSucceeded : MainIntent
    data class DenyApproval(val approvalId: String) : MainIntent
    data class StepUpAuthenticationSucceeded(val approvalId: String) : MainIntent
    data class SetScreenshotProtection(val enabled: Boolean) : MainIntent
    data object LocalAuthenticationSucceeded : MainIntent
}

@HiltViewModel
class MainViewModel @Inject constructor(
    @dagger.hilt.android.qualifiers.ApplicationContext private val appContext: Context,
    private val preferences: AppPreferencesRepository,
    private val dao: HermesDao,
    private val repository: MobileChatRepository,
    private val attachmentUploads: AttachmentUploadRepository,
    private val voiceRecorder: VoiceNoteRecorder,
    private val approvals: ApprovalRepository,
    private val pushRegistration: PushRegistrationCoordinator,
    private val enrollment: MobileEnrollmentCoordinator,
    private val api: HermesApiClient,
    private val authSession: HermesAuthSession,
    private val groups: MobileGroupRepository,
    private val settings: SettingsRepository,
) : ViewModel() {
    private val state = MutableStateFlow(MainUiState())
    private var pendingVoiceCapture: VoiceNoteCapture? = null
    private var pendingEnrollment: PendingDeviceEnrollment? = null
    private var currentSettings: SettingsResponse? = null
    private var pendingSettingsChallenge: StepUpChallengeResponse? = null
    private var pendingSensitiveChanges: JsonObject? = null
    private var currentGroup: GroupResponse? = null
    private var draftPersistJob: Job? = null
    private var draftEditGeneration = 0L
    private var conversationSelectionGeneration = 0L
    private var eventStreamJob: Job? = null
    private var conversationLoadJob: Job? = null
    private var directRunJob: Job? = null
    private val messageStatusJobs = java.util.Collections.synchronizedSet(mutableSetOf<Job>())

    init {
        refreshCachedBots()
    }

    private val clockMillis = flow {
        while (currentCoroutineContext().isActive) {
            emit(System.currentTimeMillis())
            delay(15_000)
        }
    }

    val uiState: StateFlow<MainUiState> = combine(
        state,
        preferences.preferences,
        clockMillis,
    ) { current, stored, nowMillis ->
        val lockState = LocalLockState(stored.lastUnlockedAtEpochMillis)
        current.copy(
            blockScreenshots = stored.blockScreenshots,
            isLocked = lockState.isLocked(nowMillis),
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000),
        initialValue = MainUiState(),
    )

    fun dispatch(intent: MainIntent) {
        when (intent) {
            MainIntent.Refresh -> {
                refreshNetwork()
            }
            is MainIntent.SelectBot -> {
                selectBot(intent.bot)
            }
            is MainIntent.SelectConversation -> selectConversation(intent.conversationId)
            MainIntent.CreateConversation -> createConversation()
            MainIntent.RetryCreateConversation -> retryCreateConversation()
            is MainIntent.SelectSection -> {
                if (intent.section != HomeSection.CHAT) onChatScreenHidden()
                state.update { it.copy(section = intent.section) }
                if (intent.section == HomeSection.GROUPS) {
                    refreshGroup()
                } else if (intent.section == HomeSection.CHAT) {
                    state.value.selectedBot?.let { selected ->
                        startEventStream(selected)
                        observeRun(
                            bot = selected,
                            runId = state.value.directRun.runId,
                            conversationId = state.value.selectedConversationId?.value,
                        )
                    }
                }
            }
            is MainIntent.SetDraft -> setDraft(intent.text)
            MainIntent.SendDraft -> sendDraft()
            is MainIntent.RetrySend -> retrySend(intent.operationId)
            is MainIntent.EditAsNewMessage -> requestEditAsNew(intent.operationId)
            MainIntent.ConfirmEditAsNewMessage -> confirmEditAsNew()
            MainIntent.DismissEditAsNewMessage -> state.update { it.copy(editAsNewConfirmation = null) }
            is MainIntent.CancelRun -> cancelRun(intent.runId)
            is MainIntent.RefreshRun -> refreshRun(intent.runId)
            MainIntent.AddAttachment -> state.update {
                it.copy(composerMessage = "Choose a file from the system picker to stage it privately.")
            }
            MainIntent.ClearAttachments -> clearAttachments()
            is MainIntent.AttachmentSelected -> uploadAttachment(intent.uri)
            MainIntent.ToggleVoiceNote -> toggleVoiceNote()
            MainIntent.VoicePermissionDenied -> state.update {
                it.copy(composerMessage = "Microphone permission is required only to record a voice note.")
            }
            MainIntent.SendVoiceNote -> uploadPendingVoiceNote()
            MainIntent.DiscardVoiceNote -> discardPendingVoiceNote()
            is MainIntent.ToggleGroupBot -> toggleGroupBot(intent.bot)
            MainIntent.CreateGroup -> createGroup()
            MainIntent.RefreshGroup -> refreshGroup()
            is MainIntent.AddGroupMember -> addGroupMember(intent.bot)
            is MainIntent.RemoveGroupMember -> removeGroupMember(intent.memberId)
            is MainIntent.SetGroupDraft -> state.update {
                it.copy(group = it.group.copy(draft = intent.text.take(MAX_GROUP_MESSAGE_LENGTH), message = null))
            }
            MainIntent.SendGroupMessage -> sendGroupMessage()
            MainIntent.StopGroup -> stopGroup()
            MainIntent.ClearGroup -> clearGroup()
            is MainIntent.SetDeviceLabel -> state.update {
                it.copy(enrollment = it.enrollment.copy(deviceLabel = intent.label.take(64), message = null))
            }
            MainIntent.StartEnrollment -> startEnrollment()
            MainIntent.CheckEnrollment -> checkEnrollment()
            is MainIntent.SetSettingsDisplayName -> state.update {
                it.copy(settings = it.settings.copy(draftDisplayName = intent.value.take(256), message = null))
            }
            is MainIntent.SetSettingsTitle -> state.update {
                it.copy(settings = it.settings.copy(draftTitle = intent.value.take(256), message = null))
            }
            is MainIntent.SetSettingsAvatar -> state.update {
                it.copy(settings = it.settings.copy(draftAvatar = intent.value.take(256), message = null))
            }
            is MainIntent.SetSettingsNotifications -> state.update {
                it.copy(settings = it.settings.copy(draftNotificationsEnabled = intent.enabled, message = null))
            }
            is MainIntent.SetSettingsPersona -> state.update {
                it.copy(settings = it.settings.copy(draftPersona = intent.value.take(16_384), message = null))
            }
            MainIntent.SaveSettings -> saveSafeSettings()
            MainIntent.PrepareSensitiveSettings -> prepareSensitiveSettings()
            MainIntent.SettingsStepUpAuthenticationSucceeded -> saveSensitiveSettings()
            is MainIntent.DenyApproval -> denyApproval(intent.approvalId)
            is MainIntent.StepUpAuthenticationSucceeded -> approveApproval(intent.approvalId)
            is MainIntent.SetScreenshotProtection -> viewModelScope.launch {
                preferences.setBlockScreenshots(intent.enabled)
            }
            MainIntent.LocalAuthenticationSucceeded -> viewModelScope.launch {
                preferences.recordUnlock(System.currentTimeMillis())
                refreshNetwork()
            }
        }
    }

    fun onChatScreenHidden() {
        eventStreamJob?.cancel()
        directRunJob?.cancel()
        cancelMessageStatusJobs()
        if (state.value.isRecording) {
            voiceRecorder.discard()
            state.update {
                it.copy(
                    isRecording = false,
                    composerMessage = "Voice note discarded when Hermes left the foreground.",
                )
            }
        }
        pendingVoiceCapture?.file?.delete()
        pendingVoiceCapture = null
        state.update { it.copy(pendingVoiceNoteDurationMillis = null) }
    }

    private fun startEnrollment() {
        val snapshot = state.value.enrollment
        val label = snapshot.deviceLabel.trim()
        if (label.isBlank()) {
            state.update {
                it.copy(
                    enrollment = snapshot.copy(
                        phase = EnrollmentPhase.ERROR,
                        message = "Enter a device label first.",
                    ),
                )
            }
            return
        }
        if (!enrollmentConfigurationReady()) {
            state.update {
                it.copy(
                    enrollment = snapshot.copy(
                        phase = EnrollmentPhase.ERROR,
                        message = "This release is missing its Cloudflare/OAuth build coordinates.",
                    ),
                )
            }
            return
        }
        viewModelScope.launch {
            state.update {
                it.copy(
                    enrollment = snapshot.copy(
                        phase = EnrollmentPhase.AUTHORIZING,
                        enrollmentCode = null,
                        deviceId = null,
                        message = "Opening Cloudflare Access in a secure browser tab…",
                    ),
                )
            }
            try {
                val pending = enrollment.enroll(
                    context = appContext,
                    authorization = AuthorizationStart(
                        issuer = BuildConfig.CLOUDFLARE_ISSUER,
                        resource = BuildConfig.CLOUDFLARE_RESOURCE,
                        clientId = BuildConfig.OAUTH_CLIENT_ID,
                        authorizationEndpoint = BuildConfig.OAUTH_AUTHORIZATION_ENDPOINT,
                        nowEpochMillis = System.currentTimeMillis(),
                    ),
                    tokenEndpoint = BuildConfig.OAUTH_TOKEN_ENDPOINT,
                    deviceLabel = label,
                    nowEpochMillis = System.currentTimeMillis(),
                )
                pendingEnrollment = pending
                state.update {
                    it.copy(
                        enrollment = it.enrollment.copy(
                            phase = EnrollmentPhase.AWAITING_APPROVAL,
                            deviceId = pending.response.deviceId,
                            enrollmentCode = pending.response.enrollmentCode,
                            message = "Give this one-time code to the Hermes host operator, then check approval.",
                        ),
                    )
                }
            } catch (_: Exception) {
                pendingEnrollment = null
                state.update {
                    it.copy(
                        enrollment = it.enrollment.copy(
                            phase = EnrollmentPhase.ERROR,
                            message = "Enrollment did not complete. Check the Access policy and try again.",
                        ),
                    )
                }
            }
        }
    }

    private fun setDraft(text: String) {
        val bounded = text.take(MAX_DRAFT_LENGTH)
        draftEditGeneration += 1L
        state.update { it.copy(draft = bounded, composerMessage = null) }
        persistDraftDebounced(bounded)
    }

    /** Switches profiles only after the previous conversation's draft is durably flushed. */
    private fun selectBot(target: BotId) {
        val snapshot = state.value
        if (snapshot.selectedBot == target) return
        if (snapshot.isAttachmentUploading ||
            snapshot.isRecording ||
            snapshot.pendingVoiceNoteDurationMillis != null ||
            snapshot.selectedAttachmentIds.isNotEmpty()
        ) {
            state.update {
                it.copy(composerMessage = "Send or clear the attached files and finish the voice note before switching profiles.")
            }
            return
        }
        cancelMessageStatusJobs()

        val previousBot = snapshot.selectedBot
        val previousConversationId = snapshot.selectedConversationId?.value
        val previousDraft = snapshot.draft
        conversationLoadJob?.cancel()
        draftEditGeneration += 1L
        conversationSelectionGeneration += 1L
        val switchGeneration = conversationSelectionGeneration
        if (previousBot == null || previousConversationId == null) {
            applyBotSelection(target)
            return
        }
        val botToFlush = previousBot
        val conversationToFlush = previousConversationId

        state.update {
            if (it.selectedBot != botToFlush ||
                it.selectedConversationId?.value != conversationToFlush
            ) {
                it
            } else {
                it.copy(
                    isLoadingConversations = true,
                    composerMessage = "Saving the current draft before switching profiles…",
                )
            }
        }
        viewModelScope.launch {
            if (!flushDraftBeforeNavigation(botToFlush, conversationToFlush, previousDraft)) return@launch
            if (state.value.selectedBot != botToFlush ||
                state.value.selectedConversationId?.value != conversationToFlush ||
                conversationSelectionGeneration != switchGeneration
            ) return@launch
            applyBotSelection(target)
        }
    }

    private fun applyBotSelection(target: BotId) {
        state.update {
            it.copy(
                selectedBot = target,
                selectedConversationId = null,
                conversations = emptyList(),
                conversationsStale = false,
                isLoadingConversations = false,
                draft = "",
                selectedAttachmentCount = 0,
                selectedAttachmentIds = emptyList(),
                attention = it.botCards.firstOrNull { card -> card.bot == target }
                    ?.attention ?: AttentionState.NONE,
                transcript = emptyList(),
                directRun = DirectRunUiState(),
                directRuns = emptyList(),
                pendingConversationCreate = null,
                editAsNewConfirmation = null,
                composerMessage = null,
                settings = SettingsUiState(isLoading = true),
            )
        }
        loadConversation(target)
        loadSettings(target)
        if (state.value.section == HomeSection.CHAT) startEventStream(target)
    }

    private fun persistDraftDebounced(text: String) {
        draftPersistJob?.cancel()
        val bot = state.value.selectedBot ?: return
        val conversationId = state.value.selectedConversationId?.value ?: return
        draftPersistJob = viewModelScope.launch {
            delay(DRAFT_PERSIST_DEBOUNCE_MILLIS)
            try {
                repository.saveDraft(
                    target = bot,
                    conversationId = conversationId,
                    text = text,
                    nowEpochMillis = System.currentTimeMillis(),
                )
            } catch (_: UnreadableEncryptedValueException) {
                invalidateSensitiveState("Encrypted draft state was invalidated. Re-enroll this device.")
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                if (state.value.selectedBot == bot &&
                    state.value.selectedConversationId?.value == conversationId
                ) {
                    state.update { it.copy(composerMessage = "Draft could not be saved locally; it remains in memory.") }
                }
            }
        }
    }

    /** Flushes the draft that belongs to the old selection before navigation changes its scope. */
    private suspend fun flushDraftBeforeNavigation(
        bot: BotId,
        conversationId: String?,
        text: String,
    ): Boolean {
        draftPersistJob?.cancel()
        if (conversationId == null) return true
        return try {
            repository.saveDraft(
                target = bot,
                conversationId = conversationId,
                text = text,
                nowEpochMillis = System.currentTimeMillis(),
            )
            true
        } catch (_: UnreadableEncryptedValueException) {
            invalidateSensitiveState("Encrypted draft state was invalidated. Re-enroll this device.")
            false
        } catch (cancelled: CancellationException) {
            throw cancelled
        } catch (_: Exception) {
            if (state.value.selectedBot == bot &&
                state.value.selectedConversationId?.value == conversationId
            ) {
                state.update {
                    it.copy(
                        isLoadingConversations = false,
                        composerMessage = "The draft could not be saved; finish reconnecting before switching conversations.",
                    )
                }
            }
            false
        }
    }

    private fun checkEnrollment() {
        val pending = pendingEnrollment
        if (pending == null) {
            state.update {
                it.copy(
                    enrollment = it.enrollment.copy(
                        phase = EnrollmentPhase.ERROR,
                        message = "Start enrollment again; the pending OAuth result is no longer held in memory.",
                    ),
                )
            }
            return
        }
        viewModelScope.launch {
            state.update {
                it.copy(
                    enrollment = it.enrollment.copy(
                        phase = EnrollmentPhase.CONNECTING,
                        message = "Checking host approval…",
                    ),
                )
            }
            try {
                val device = api.listDevices(pending.accessToken).devices.firstOrNull { candidate ->
                    candidate.deviceId == pending.response.deviceId
                }
                when {
                    device == null -> state.update {
                        it.copy(
                            enrollment = it.enrollment.copy(
                                phase = EnrollmentPhase.AWAITING_APPROVAL,
                                message = "The host has not approved this device yet.",
                            ),
                        )
                    }
                    !device.status.equals("approved", ignoreCase = true) -> state.update {
                        it.copy(
                            enrollment = it.enrollment.copy(
                                phase = EnrollmentPhase.AWAITING_APPROVAL,
                                message = "The device is still ${device.status}; wait for host approval.",
                            ),
                        )
                    }
                    device.profiles.isEmpty() -> state.update {
                        it.copy(
                            enrollment = it.enrollment.copy(
                                phase = EnrollmentPhase.ERROR,
                                message = "The host approved this device without a profile allowlist.",
                            ),
                        )
                    }
                    else -> {
                        val profile = device.profiles.first()
                        enrollment.establishApprovedSession(
                            pending = pending,
                            instanceId = profile.instanceId,
                            opaqueProfileId = profile.opaqueProfileId,
                            nowEpochMillis = System.currentTimeMillis(),
                        )
                        pendingEnrollment = null
                        state.update {
                            it.copy(
                                enrollment = it.enrollment.copy(
                                    phase = EnrollmentPhase.CONNECTED,
                                    enrollmentCode = null,
                                    message = "Device approved. Loading the scoped Hermes roster…",
                                ),
                            )
                        }
                        refreshNetwork()
                    }
                }
            } catch (_: Exception) {
                state.update {
                    it.copy(
                        enrollment = it.enrollment.copy(
                            phase = EnrollmentPhase.AWAITING_APPROVAL,
                            message = "Approval check failed; retry when the tunnel is available.",
                        ),
                    )
                }
            }
        }
    }

    private fun enrollmentConfigurationReady(): Boolean = listOf(
        BuildConfig.MOBILE_BASE_URL,
        BuildConfig.CLOUDFLARE_ISSUER,
        BuildConfig.CLOUDFLARE_RESOURCE,
        BuildConfig.OAUTH_CLIENT_ID,
        BuildConfig.OAUTH_AUTHORIZATION_ENDPOINT,
        BuildConfig.OAUTH_TOKEN_ENDPOINT,
    ).all { value ->
        value.isNotBlank() &&
            !value.contains("invalid.invalid") &&
            !value.contains("configure-at-build-time")
    }

    private fun refreshNetwork() {
        viewModelScope.launch {
            state.update {
                it.copy(
                    transport = TransportState.STALE,
                    composerMessage = "Refreshing the approved Hermes roster…",
                )
            }
            try {
                val roster = repository.restoreAndListProfiles(System.currentTimeMillis())
                if (roster == null) {
                    refreshCachedBots()
                    state.update {
                        it.copy(
                            transport = TransportState.DISCONNECTED,
                            composerMessage = "Connect this device with PKCE and host approval before syncing.",
                        )
                    }
                    return@launch
                }
                // Token registration is best-effort: the FCM token stays encrypted locally and
                // is retried on the next authenticated refresh if the relay is unavailable.
                try {
                    pushRegistration.registerIfAuthenticated()
                } catch (_: AuthenticationCacheInvalidatedException) {
                    invalidateSensitiveState("Encrypted push state was invalidated. Re-enroll this device.")
                    return@launch
                } catch (_: Exception) {
                    // Keep the encrypted token for the next foreground/worker retry.
                }
                val cards = roster.profiles.map { profile ->
                    BotCardState(
                        bot = profile.bot.toContractBot(),
                        displayName = profile.label,
                        originLabel = "Instance ${presentationTail(profile.bot.instanceId)}",
                        transport = TransportState.CONNECTED,
                    )
                }
                val previousSelectedBot = state.value.selectedBot
                val selectedBot = previousSelectedBot?.takeIf { bot -> cards.any { it.bot == bot } }
                    ?: cards.firstOrNull()?.bot
                if (selectedBot != previousSelectedBot) {
                    conversationSelectionGeneration += 1L
                }
                state.update { current ->
                    val availableBots = cards.map { it.bot }.toSet()
                    current.copy(
                        bots = cards.map { it.bot },
                        botCards = cards,
                        selectedBot = selectedBot,
                        group = current.group.copy(
                            selectedBotIds = current.group.selectedBotIds.filter { bot -> bot in availableBots },
                        ),
                        transport = TransportState.CONNECTED,
                        composerMessage = null,
                    )
                }
                for (profile in roster.profiles) {
                    try {
                        repository.reconcile(profile.bot.toContractBot(), System.currentTimeMillis())
                    } catch (_: Exception) {
                        // The roster remains usable while an individual profile catches up.
                    }
                }
                refreshApprovals()
                state.value.selectedBot?.let { selected ->
                    loadConversation(selected)
                    loadSettings(selected)
                    if (state.value.section == HomeSection.CHAT) startEventStream(selected)
                }
                refreshGroup()
            } catch (_: HermesAuthExpiredException) {
                state.update {
                    it.copy(
                        transport = TransportState.AUTH_EXPIRED,
                        composerMessage = "This device session expired. Re-enroll or approve it again.",
                    )
                }
            } catch (_: AuthenticationCacheInvalidatedException) {
                invalidateSensitiveState("Encrypted device state was invalidated. Re-enroll this device.")
            } catch (error: HermesApiException) {
                state.update {
                    it.copy(
                        transport = TransportState.STALE,
                        composerMessage = "Hermes request failed (${error.statusCode}); retry when the tunnel is healthy.",
                    )
                }
            } catch (_: java.io.IOException) {
                state.update {
                    it.copy(
                        transport = TransportState.DISCONNECTED,
                        composerMessage = "Hermes is unreachable. Check the Cloudflare tunnel and retry.",
                    )
                }
            }
        }
    }

    /** Keeps the selected profile live without treating an SSE connection as the source of truth. */
    private fun startEventStream(bot: BotId) {
        eventStreamJob?.cancel()
        eventStreamJob = viewModelScope.launch {
            while (isActive && state.value.selectedBot == bot && state.value.section == HomeSection.CHAT) {
                try {
                    val cursor = repository.currentSyncCursor(bot)
                    val response = repository.openEventStream(
                        target = bot,
                        afterCursor = cursor,
                        nowEpochMillis = System.currentTimeMillis(),
                    )
                    val applied = try {
                        repository.consumeEventStream(bot, response)
                    } finally {
                        response.close()
                    }
                    if (applied > 0 && state.value.selectedBot == bot) {
                        loadConversation(bot)
                        refreshApprovals()
                    }
                } catch (_: CursorExpiredException) {
                    try {
                        repository.reconcile(
                            target = bot,
                            nowEpochMillis = System.currentTimeMillis(),
                            forceSnapshot = true,
                        )
                        if (state.value.selectedBot == bot) loadConversation(bot)
                    } catch (_: HermesAuthExpiredException) {
                        state.update { it.copy(transport = TransportState.AUTH_EXPIRED) }
                        return@launch
                    } catch (_: AuthenticationCacheInvalidatedException) {
                        invalidateSensitiveState("Encrypted device state was invalidated. Re-enroll this device.")
                        return@launch
                    } catch (_: UnreadableEncryptedValueException) {
                        invalidateSensitiveState("Encrypted sync state was invalidated. Re-enroll this device.")
                        return@launch
                    } catch (_: HermesApiException) {
                        // Retry the full snapshot on the next stream iteration.
                    } catch (_: java.io.IOException) {
                        // Retry the full snapshot on the next stream iteration.
                    }
                } catch (_: HermesAuthExpiredException) {
                    state.update {
                        it.copy(
                            transport = TransportState.AUTH_EXPIRED,
                            composerMessage = "Session expired; re-enroll or approve this device again.",
                        )
                    }
                    return@launch
                } catch (_: AuthenticationCacheInvalidatedException) {
                    invalidateSensitiveState("Encrypted device state was invalidated. Re-enroll this device.")
                    return@launch
                } catch (_: UnreadableEncryptedValueException) {
                    invalidateSensitiveState("Encrypted sync state was invalidated. Re-enroll this device.")
                    return@launch
                } catch (_: HermesApiException) {
                    // Reopen with the durable cursor after transient server or tunnel failures.
                } catch (_: java.io.IOException) {
                    // A disconnected tunnel is expected to recover through the same cursor.
                }
                delay(EVENT_STREAM_RECONNECT_DELAY_MILLIS)
            }
        }
    }

    private fun loadConversation(bot: BotId, requestedConversationId: String? = null) {
        val loadDraftGeneration = draftEditGeneration
        val loadSelectionGeneration = conversationSelectionGeneration
        conversationLoadJob?.cancel()
        state.update {
            if (it.selectedBot == bot) {
                it.copy(isLoadingConversations = true, composerMessage = null)
            } else {
                it
            }
        }
        conversationLoadJob = viewModelScope.launch {
            val pendingCreateBeforeLoad = runCatching {
                repository.pendingConversationCreate(bot)
            }.getOrNull()
            try {
                val loaded = repository.loadConversation(
                    target = bot,
                    nowEpochMillis = System.currentTimeMillis(),
                    requestedConversationId = requestedConversationId,
                )
                if (!isCurrentConversationLoad(bot, loadSelectionGeneration)) return@launch
                if (loaded == null) {
                    state.update {
                        if (!isCurrentConversationLoad(bot, loadSelectionGeneration)) return@update it
                        it.copy(
                            selectedConversationId = null,
                            conversations = emptyList(),
                            conversationsStale = false,
                            isLoadingConversations = false,
                            transcript = emptyList(),
                            directRun = DirectRunUiState(),
                            directRuns = emptyList(),
                            pendingConversationCreate = pendingCreateBeforeLoad,
                            draft = if (draftEditGeneration == loadDraftGeneration) "" else it.draft,
                        )
                    }
                    return@launch
                }
                val transcript = transcriptCards(loaded.messages)
                val pendingSends = repository.listPendingSends(bot, loaded.conversation.conversationId)
                val pendingCards = pendingSends.map(::pendingSendCard)
                val pendingCreate = repository.pendingConversationCreate(bot)
                val savedDraft = repository.loadDraft(bot, loaded.conversation.conversationId)
                val cachedRun = repository.loadCachedRun(bot, loaded.conversation.conversationId)
                state.update {
                    if (!isCurrentConversationLoad(bot, loadSelectionGeneration)) return@update it
                    it.copy(
                        selectedConversationId = ConversationId(loaded.conversation.conversationId),
                        conversations = loaded.conversations.map(::conversationCard),
                        conversationsStale = false,
                        isLoadingConversations = false,
                        transcript = mergeTranscriptCards(transcript, pendingCards),
                        directRun = cachedRun?.toDirectRunUiState() ?: DirectRunUiState(),
                        directRuns = cachedRun?.toDirectRunUiState()?.let(::visibleDirectRuns)
                            ?: emptyList(),
                        pendingConversationCreate = pendingCreate,
                        draft = if (draftEditGeneration == loadDraftGeneration) savedDraft ?: "" else it.draft,
                        transport = TransportState.CONNECTED,
                        composerMessage = null,
                    )
                }
                if (!isCurrentConversationLoad(bot, loadSelectionGeneration)) return@launch
                observeRun(
                    bot = bot,
                    runId = cachedRun?.runId,
                    conversationId = loaded.conversation.conversationId,
                )
            } catch (_: HermesAuthExpiredException) {
                if (!isCurrentConversationLoad(bot, loadSelectionGeneration)) return@launch
                state.update {
                    it.copy(
                        isLoadingConversations = false,
                        pendingConversationCreate = pendingCreateBeforeLoad,
                        transport = TransportState.AUTH_EXPIRED,
                    )
                }
            } catch (_: AuthenticationCacheInvalidatedException) {
                if (!isCurrentConversationLoad(bot, loadSelectionGeneration)) return@launch
                invalidateSensitiveState("Encrypted device state was invalidated. Re-enroll this device.")
            } catch (error: HermesApiException) {
                if (!isCurrentConversationLoad(bot, loadSelectionGeneration)) return@launch
                if (!presentCachedConversation(bot, loadDraftGeneration, loadSelectionGeneration, TransportState.STALE)) {
                    state.update {
                        it.copy(
                            isLoadingConversations = false,
                            pendingConversationCreate = pendingCreateBeforeLoad,
                            conversationsStale = true,
                            composerMessage = "Could not load this conversation (${error.statusCode}).",
                        )
                    }
                }
            } catch (_: java.io.IOException) {
                if (!isCurrentConversationLoad(bot, loadSelectionGeneration)) return@launch
                if (!presentCachedConversation(bot, loadDraftGeneration, loadSelectionGeneration, TransportState.DISCONNECTED)) {
                    state.update {
                        it.copy(
                            isLoadingConversations = false,
                            pendingConversationCreate = pendingCreateBeforeLoad,
                            conversationsStale = true,
                            transport = TransportState.DISCONNECTED,
                            composerMessage = "Hermes is unreachable and no encrypted conversation snapshot is available.",
                        )
                    }
                }
            } catch (_: MobileChatRepository.ConversationNotFoundException) {
                if (!isCurrentConversationLoad(bot, loadSelectionGeneration)) return@launch
                state.update {
                    it.copy(
                        isLoadingConversations = false,
                        pendingConversationCreate = pendingCreateBeforeLoad,
                        composerMessage = "That conversation is no longer available to this profile.",
                    )
                }
            } catch (_: UnreadableEncryptedValueException) {
                if (!isCurrentConversationLoad(bot, loadSelectionGeneration)) return@launch
                invalidateSensitiveState("Encrypted conversation state was invalidated. Re-enroll this device.")
            }
        }
    }

    private fun isCurrentConversationLoad(bot: BotId, generation: Long): Boolean =
        state.value.selectedBot == bot && conversationSelectionGeneration == generation

    private fun transcriptCards(messages: List<com.hermes.mobile.network.ConversationMessageWire>): List<TranscriptCard> =
        messages.mapNotNull { message ->
            val parts = repository.messageParts(message)
            if (parts.isEmpty()) return@mapNotNull null
            TranscriptCard(
                messageId = message.messageId,
                authorLabel = when (message.role.lowercase()) {
                    "user" -> "You"
                    "system" -> "Hermes"
                    else -> "Hermes bot",
                },
                role = when (message.role.lowercase()) {
                    "user" -> TranscriptRole.USER
                    "system" -> TranscriptRole.SYSTEM
                    else -> TranscriptRole.BOT
                },
                parts = parts,
                operationId = operationIdFromLocalMessageId(message.messageId),
            )
        }

    /**
     * Merges server history with durable local operation cards without text-based de-duplication.
     * The only accepted identity link is the stable local-${operationId} marker (or an operation
     * ID already attached to a projected card), so two intentionally equal messages remain two
     * messages.
     */
    private fun mergeTranscriptCards(
        authoritative: List<TranscriptCard>,
        pending: List<TranscriptCard>,
    ): List<TranscriptCard> {
        val history = authoritative.distinctBy(TranscriptCard::messageId)
        val pendingByOperationId = pending
            .mapNotNull { card -> card.operationId?.let { it to card } }
            .toMap()
        val mergedHistory = history.map { card ->
            val pendingCard = card.operationId?.let(pendingByOperationId::get)
            if (pendingCard == null) {
                card
            } else {
                // Keep the authoritative parts/message ID, but carry the exact durable operation
                // metadata back onto its local marker after a reload. This is a merge, not a
                // second transcript card, and preserves retry/edit controls for active sends.
                card.copy(
                    delivery = pendingCard.delivery,
                    runState = pendingCard.runState ?: card.runState,
                    operationState = pendingCard.operationState,
                    runId = pendingCard.runId,
                )
            }
        }
        val historyOperationIds = mergedHistory.mapNotNull(TranscriptCard::operationId).toSet()
        return mergedHistory + pending.filter { card ->
            val operationId = card.operationId ?: return@filter false
            operationId !in historyOperationIds &&
                mergedHistory.none { it.messageId == "local-$operationId" }
        }
    }

    private fun pendingSendCard(send: com.hermes.mobile.data.PendingSend): TranscriptCard =
        TranscriptCard(
            messageId = "pending-${send.operationId}",
            authorLabel = "You",
            role = TranscriptRole.USER,
            // Keep the exact opaque attachment references visible on the durable pending card.
            // They are intentionally rendered as generic files until the host supplies the
            // authoritative MIME/display metadata; dropping them here would make a retry appear
            // to contain a different payload than the encrypted operation.
            parts = pendingMessageParts(send.text, send.attachmentIds),
            // After a process restart the transport outcome is unknown.  Keep the card visibly
            // retryable; retry first performs the read-only status lookup before replaying.
            delivery = if (send.state in MobileOperationStates.ACTIVE &&
                send.state !in MobileOperationStates.REVIEWABLE
            ) DeliveryState.PENDING else DeliveryState.FAILED,
            runState = send.runId?.let { send.state.toRunState() },
            operationId = send.operationId,
            operationState = send.state,
            runId = send.runId,
        )

    private fun pendingMessageParts(text: String, attachmentIds: List<String>): List<MessagePart> =
        buildList(attachmentIds.size + 1) {
            if (text.isNotBlank()) add(MessagePart.Text(text))
            attachmentIds.forEach { attachmentId ->
                add(MessagePart.File(attachmentId = attachmentId))
            }
        }

    private fun conversationCard(value: ConversationWire): ConversationCardState = ConversationCardState(
        conversationId = value.conversationId,
        title = value.title.ifBlank { "Conversation" },
        canonical = value.canonical,
        updatedAtEpochMillis = (value.updatedAtEpochSeconds * 1_000).toLong(),
    )

    private suspend fun presentCachedConversation(
        bot: BotId,
        loadDraftGeneration: Long,
        loadSelectionGeneration: Long,
        transport: TransportState,
    ): Boolean {
        return try {
            if (!isCurrentConversationLoad(bot, loadSelectionGeneration)) return false
            val cached = repository.loadCachedConversation(bot) ?: return false
            val transcript = transcriptCards(cached.messages)
            val pendingSends = repository.listPendingSends(bot, cached.conversation.conversationId)
            val pendingCards = pendingSends.map(::pendingSendCard)
            val pendingCreate = repository.pendingConversationCreate(bot)
            val savedDraft = repository.loadDraft(bot, cached.conversation.conversationId)
            val cachedRun = repository.loadCachedRun(bot, cached.conversation.conversationId)
            state.update {
                if (!isCurrentConversationLoad(bot, loadSelectionGeneration)) return@update it
                it.copy(
                    selectedConversationId = ConversationId(cached.conversation.conversationId),
                    conversations = cached.conversations.map(::conversationCard),
                    conversationsStale = true,
                    isLoadingConversations = false,
                    transcript = mergeTranscriptCards(transcript, pendingCards),
                    directRun = cachedRun?.toDirectRunUiState() ?: DirectRunUiState(),
                    directRuns = cachedRun?.toDirectRunUiState()?.let(::visibleDirectRuns)
                        ?: emptyList(),
                    pendingConversationCreate = pendingCreate,
                    draft = if (draftEditGeneration == loadDraftGeneration) savedDraft ?: "" else it.draft,
                    transport = transport,
                    composerMessage = "Showing the last encrypted conversation snapshot; reconnect to refresh.",
                )
            }
            if (!isCurrentConversationLoad(bot, loadSelectionGeneration)) return false
            observeRun(
                bot = bot,
                runId = cachedRun?.runId,
                conversationId = cached.conversation.conversationId,
            )
            true
        } catch (_: UnreadableEncryptedValueException) {
            invalidateSensitiveState("Encrypted conversation state was invalidated. Re-enroll this device.")
            true
        }
    }

    private fun selectConversation(conversationId: String) {
        val snapshot = state.value
        val bot = snapshot.selectedBot ?: run {
            state.update { it.copy(composerMessage = "Select an approved bot before choosing a conversation.") }
            return
        }
        if (snapshot.isAttachmentUploading ||
            snapshot.isRecording ||
            snapshot.pendingVoiceNoteDurationMillis != null ||
            snapshot.selectedAttachmentIds.isNotEmpty()
        ) {
            state.update {
                it.copy(composerMessage = "Send or clear the attached files and finish the voice note before switching conversations.")
            }
            return
        }
        if (snapshot.isLoadingConversations || snapshot.selectedConversationId?.value == conversationId) return
        if (snapshot.conversations.none { it.conversationId == conversationId }) {
            state.update { it.copy(composerMessage = "That conversation is not in the approved profile roster.") }
            return
        }
        // Status polling belongs to the visible conversation.  The encrypted operation remains
        // durable and is picked up again when the user returns or explicitly retries it.
        cancelMessageStatusJobs()
        val previousConversationId = snapshot.selectedConversationId?.value
        val previousDraft = snapshot.draft
        conversationLoadJob?.cancel()
        conversationSelectionGeneration += 1L
        draftEditGeneration += 1L
        state.update {
            it.copy(
                isLoadingConversations = true,
                composerMessage = "Saving the current draft…",
            )
        }
        viewModelScope.launch {
            if (!flushDraftBeforeNavigation(bot, previousConversationId, previousDraft)) return@launch
            if (state.value.selectedBot != bot ||
                state.value.selectedConversationId?.value != previousConversationId
            ) return@launch
            state.update {
                it.copy(
                    selectedConversationId = ConversationId(conversationId),
                    transcript = emptyList(),
                    draft = "",
                    directRun = DirectRunUiState(),
                    directRuns = emptyList(),
                    composerMessage = "Loading conversation…",
                )
            }
            loadConversation(bot, requestedConversationId = conversationId)
        }
    }

    private fun createConversation() {
        beginConversationCreate(operationId = null)
    }

    private fun retryCreateConversation() {
        val pending = state.value.pendingConversationCreate
        if (pending == null) {
            state.update { it.copy(composerMessage = "There is no unresolved New chat request to retry.") }
            return
        }
        when (conversationCreateRecoveryAction(pending)) {
            ConversationCreateRecoveryAction.RETRY_ORIGINAL ->
                beginConversationCreate(operationId = pending.operationId)
            ConversationCreateRecoveryAction.WAIT -> state.update {
                it.copy(composerMessage = "The New chat request is still in progress; retry it after it becomes unresolved.")
            }
            ConversationCreateRecoveryAction.NONE -> Unit
        }
    }

    private fun beginConversationCreate(operationId: String?) {
        val snapshot = state.value
        val bot = snapshot.selectedBot ?: run {
            state.update { it.copy(composerMessage = "Select an approved bot before starting a new chat.") }
            return
        }
        if (operationId == null &&
            conversationCreateRecoveryAction(snapshot.pendingConversationCreate) != ConversationCreateRecoveryAction.NONE
        ) {
            state.update {
                it.copy(composerMessage = "A New chat request is unresolved; retry that request explicitly first.")
            }
            return
        }
        if (snapshot.isAttachmentUploading ||
            snapshot.isRecording ||
            snapshot.pendingVoiceNoteDurationMillis != null ||
            snapshot.selectedAttachmentIds.isNotEmpty()
        ) {
            state.update {
                it.copy(composerMessage = "Send or clear the attached files and finish the voice note before starting a new chat.")
            }
            return
        }
        val previousConversationId = snapshot.selectedConversationId?.value
        val previousDraft = snapshot.draft
        conversationLoadJob?.cancel()
        conversationSelectionGeneration += 1L
        draftEditGeneration += 1L
        viewModelScope.launch {
            state.update { it.copy(isLoadingConversations = true, composerMessage = "Saving the current draft…") }
            if (!flushDraftBeforeNavigation(bot, previousConversationId, previousDraft)) return@launch
            if (state.value.selectedBot != bot ||
                state.value.selectedConversationId?.value != previousConversationId
            ) return@launch
            state.update { it.copy(composerMessage = "Creating a new conversation…") }
            try {
                val created = if (operationId == null) {
                    repository.createConversation(
                        target = bot,
                        nowEpochMillis = System.currentTimeMillis(),
                    )
                } else {
                    repository.retryCreateConversation(
                        target = bot,
                        operationId = operationId,
                        nowEpochMillis = System.currentTimeMillis(),
                    )
                }
                if (state.value.selectedBot != bot) return@launch
                draftPersistJob?.cancel()
                draftEditGeneration += 1L
                state.update {
                    it.copy(
                        selectedConversationId = ConversationId(created.conversationId),
                        transcript = emptyList(),
                        draft = "",
                        directRun = DirectRunUiState(),
                        directRuns = emptyList(),
                        pendingConversationCreate = null,
                    )
                }
                loadConversation(bot, requestedConversationId = created.conversationId)
            } catch (error: HermesApiException) {
                if (state.value.selectedBot == bot) {
                    val pending = repository.pendingConversationCreate(bot)
                    state.update {
                        it.copy(
                            isLoadingConversations = false,
                            pendingConversationCreate = pending,
                            transport = if (error.statusCode == 401) {
                                TransportState.AUTH_EXPIRED
                            } else {
                                it.transport
                            },
                            composerMessage = if (error.statusCode == 401) {
                                "Authentication expired before New chat completed; restore authentication, then retry the same request."
                            } else if (pending != null) {
                                "New conversation could not be created (${error.statusCode}); use Retry new chat to reuse the same request safely."
                            } else {
                                "New conversation was rejected (${error.statusCode}); you may try New chat again."
                            },
                        )
                    }
                }
            } catch (_: HermesAuthExpiredException) {
                if (state.value.selectedBot == bot) {
                    val pending = repository.pendingConversationCreate(bot)
                    state.update {
                        it.copy(
                            isLoadingConversations = false,
                            pendingConversationCreate = pending,
                            transport = TransportState.AUTH_EXPIRED,
                            composerMessage = "Session expired before New chat completed; restore authentication, then retry the same request.",
                        )
                    }
                }
            } catch (_: AuthenticationCacheInvalidatedException) {
                if (state.value.selectedBot == bot) {
                    invalidateSensitiveState("Encrypted device state was invalidated. Re-enroll this device.")
                }
            } catch (_: java.io.IOException) {
                if (state.value.selectedBot == bot) {
                    val pending = repository.pendingConversationCreate(bot)
                    state.update {
                        it.copy(
                            isLoadingConversations = false,
                            pendingConversationCreate = pending,
                            transport = TransportState.DISCONNECTED,
                            composerMessage = "New conversation could not reach Hermes; reconnect, then use Retry new chat.",
                        )
                    }
                }
            } catch (_: MobileOperationInProgressException) {
                if (state.value.selectedBot == bot) {
                    val pending = repository.pendingConversationCreate(bot)
                    state.update {
                        it.copy(
                            isLoadingConversations = false,
                            pendingConversationCreate = pending,
                            composerMessage = "A New chat request is already unresolved; retry it explicitly instead of creating another.",
                        )
                    }
                }
            } catch (_: IllegalArgumentException) {
                if (state.value.selectedBot == bot) {
                    val pending = repository.pendingConversationCreate(bot)
                    state.update {
                        it.copy(
                            isLoadingConversations = false,
                            pendingConversationCreate = pending,
                            composerMessage = "The saved New chat request is no longer retryable; use New chat to create a fresh request.",
                        )
                    }
                }
            }
        }
    }

    private fun toggleGroupBot(bot: BotId) {
        val snapshot = state.value.group
        if (snapshot.groupId != null) return
        val selected = if (bot in snapshot.selectedBotIds) {
            snapshot.selectedBotIds - bot
        } else if (snapshot.selectedBotIds.size < MAX_GROUP_MEMBERS) {
            snapshot.selectedBotIds + bot
        } else {
            state.update {
                it.copy(group = snapshot.copy(message = "A group can contain at most six bots."))
            }
            return
        }
        state.update {
            it.copy(group = it.group.copy(selectedBotIds = selected, message = null))
        }
    }

    private fun createGroup() {
        val selectedBots = state.value.group.selectedBotIds
        if (selectedBots.size !in MIN_GROUP_MEMBERS..MAX_GROUP_MEMBERS) {
            state.update {
                it.copy(group = it.group.copy(message = "Choose between two and six approved bots."))
            }
            return
        }
        viewModelScope.launch {
            state.update {
                it.copy(group = it.group.copy(isMutating = true, message = "Creating group…"))
            }
            try {
                val response = groups.createGroup(selectedBots, System.currentTimeMillis())
                currentGroup = response
                state.update {
                    it.copy(
                        group = it.group.from(response).copy(
                            isMutating = false,
                            message = "Group created with ${response.members.size} bots.",
                        ),
                    )
                }
            } catch (error: HermesApiException) {
                showGroupError("Group could not be created (${error.statusCode}).")
            } catch (_: AuthenticationCacheInvalidatedException) {
                showGroupAuthError("Encrypted device state was invalidated. Re-enroll this device.")
            } catch (_: HermesAuthExpiredException) {
                showGroupSessionExpired("Session expired before the group could be created.")
            } catch (_: java.io.IOException) {
                showGroupError("Group creation paused; retry when the tunnel is available.")
            } catch (_: IllegalArgumentException) {
                showGroupError("The selected bots cannot be used for this group.")
            }
        }
    }

    private fun refreshGroup() {
        if (state.value.group.isLoading || state.value.group.isMutating) return
        viewModelScope.launch {
            state.update { it.copy(group = it.group.copy(isLoading = true, message = null)) }
            try {
                val current = currentGroup
                val expectedGroupId = current?.groupId
                val response = if (current != null) {
                    groups.loadGroup(current, System.currentTimeMillis())
                } else {
                    val now = System.currentTimeMillis()
                    try {
                        groups.listGroups(now).firstOrNull()
                    } catch (error: HermesApiException) {
                        // Older hosts may expose only the single-group route. Keep the durable
                        // opaque reference as a compatibility fallback, still subject to the
                        // same authenticated GET and profile checks.
                        if (error.statusCode != 404) throw error
                        groups.cachedGroups().firstOrNull()?.let { cached ->
                            groups.loadCachedGroup(cached, now)
                        }
                    } ?: run {
                        state.update { it.copy(group = it.group.copy(isLoading = false)) }
                        return@launch
                    }
                }
                val observedGroupId = currentGroup?.groupId
                if ((expectedGroupId != null && response.groupId != expectedGroupId) ||
                    (expectedGroupId == null && observedGroupId != null && response.groupId != observedGroupId)
                ) {
                    state.update { it.copy(group = it.group.copy(isLoading = false)) }
                    return@launch
                }
                currentGroup = response
                state.update {
                    it.copy(group = it.group.from(response).copy(isLoading = false, message = null))
                }
            } catch (error: HermesApiException) {
                state.update {
                    it.copy(
                        group = it.group.copy(
                            isLoading = false,
                            message = "Group could not be refreshed (${error.statusCode}).",
                        ),
                    )
                }
            } catch (_: AuthenticationCacheInvalidatedException) {
                showGroupAuthError("Encrypted device state was invalidated. Re-enroll this device.")
            } catch (_: HermesAuthExpiredException) {
                showGroupSessionExpired("Session expired before the group could be refreshed.")
            } catch (_: java.io.IOException) {
                showGroupError("Group refresh is unavailable while the tunnel is offline.")
            } catch (_: IllegalArgumentException) {
                showGroupError("The host returned invalid group metadata.")
            }
        }
    }

    private fun addGroupMember(bot: BotId) {
        val group = currentGroup ?: run {
            showGroupError("Create a group before adding a member.")
            return
        }
        if (state.value.group.isMutating) return
        viewModelScope.launch {
            state.update { it.copy(group = it.group.copy(isMutating = true, message = "Updating group members…")) }
            try {
                val response = groups.addMember(group, bot, System.currentTimeMillis())
                publishGroup(response, "Group member added.")
            } catch (error: HermesApiException) {
                if (error.statusCode == 409) {
                    refreshGroupAfterConflict(group)
                } else {
                    showGroupError("Group member was not added (${error.statusCode}).")
                }
            } catch (_: AuthenticationCacheInvalidatedException) {
                showGroupAuthError("Encrypted device state was invalidated. Re-enroll this device.")
            } catch (_: HermesAuthExpiredException) {
                showGroupSessionExpired("Session expired before the group could be updated.")
            } catch (_: java.io.IOException) {
                showGroupError("Group update paused; retry when the tunnel is available.")
            } catch (_: IllegalArgumentException) {
                showGroupError("That bot cannot be added to this group.")
            }
        }
    }

    private fun removeGroupMember(memberId: String) {
        val group = currentGroup ?: run {
            showGroupError("Create a group before removing a member.")
            return
        }
        if (state.value.group.isMutating) return
        viewModelScope.launch {
            state.update { it.copy(group = it.group.copy(isMutating = true, message = "Updating group members…")) }
            try {
                val response = groups.removeMember(group, memberId, System.currentTimeMillis())
                publishGroup(response, "Group member removed.")
            } catch (error: HermesApiException) {
                if (error.statusCode == 409) {
                    refreshGroupAfterConflict(group)
                } else {
                    showGroupError("Group member was not removed (${error.statusCode}).")
                }
            } catch (_: AuthenticationCacheInvalidatedException) {
                showGroupAuthError("Encrypted device state was invalidated. Re-enroll this device.")
            } catch (_: HermesAuthExpiredException) {
                showGroupSessionExpired("Session expired before the group could be updated.")
            } catch (_: java.io.IOException) {
                showGroupError("Group update paused; retry when the tunnel is available.")
            } catch (_: IllegalArgumentException) {
                showGroupError("That member cannot be removed from this group.")
            }
        }
    }

    private fun sendGroupMessage() {
        val group = currentGroup ?: run {
            showGroupError("Create a group before sending a group message.")
            return
        }
        val text = state.value.group.draft.trim()
        if (text.isBlank()) {
            state.update { it.copy(group = it.group.copy(message = "Write a group message before sending.")) }
            return
        }
        if (state.value.group.isMutating) return
        viewModelScope.launch {
            state.update { it.copy(group = it.group.copy(isMutating = true, message = "Sending group turn…")) }
            try {
                val response = groups.sendMessage(group, text, nowEpochMillis = System.currentTimeMillis())
                publishGroupRun(response.runId, response.state)
            } catch (error: HermesApiException) {
                val message = if (error.statusCode == 409) {
                    "Group turn outcome is uncertain; refresh the group before sending again."
                } else {
                    "Group message was not sent (${error.statusCode})."
                }
                showGroupError(message)
            } catch (_: AuthenticationCacheInvalidatedException) {
                showGroupAuthError("Encrypted device state was invalidated. Re-enroll this device.")
            } catch (_: HermesAuthExpiredException) {
                showGroupSessionExpired("Session expired before the group turn could start.")
            } catch (_: java.io.IOException) {
                showGroupError("Group message paused; inspect the group run before retrying.")
            } catch (_: IllegalArgumentException) {
                showGroupError("The group message is invalid or the group is no longer active.")
            }
        }
    }

    private fun stopGroup() {
        val group = currentGroup ?: run {
            showGroupError("Create a group before stopping it.")
            return
        }
        if (state.value.group.isMutating) return
        viewModelScope.launch {
            state.update { it.copy(group = it.group.copy(isMutating = true, message = "Stopping group…")) }
            try {
                val response = groups.stopGroup(group, System.currentTimeMillis())
                publishGroup(response, "Group stopped. Its members and turns are now read-only.")
            } catch (error: HermesApiException) {
                if (error.statusCode == 409) {
                    refreshGroupAfterConflict(group)
                } else {
                    showGroupError("Group could not be stopped (${error.statusCode}).")
                }
            } catch (_: AuthenticationCacheInvalidatedException) {
                showGroupAuthError("Encrypted device state was invalidated. Re-enroll this device.")
            } catch (_: HermesAuthExpiredException) {
                showGroupSessionExpired("Session expired before the group could be stopped.")
            } catch (_: java.io.IOException) {
                showGroupError("Group stop paused; retry when the tunnel is available.")
            } catch (_: IllegalArgumentException) {
                showGroupError("The host returned invalid group metadata.")
            }
        }
    }

    private fun clearGroup() {
        if (state.value.group.lifecycle == GroupLifecycle.ACTIVE) return
        val group = currentGroup
        currentGroup = null
        state.update { it.copy(group = GroupUiState()) }
        group?.let { cached ->
            viewModelScope.launch {
                try {
                    groups.forgetGroup(cached)
                } catch (_: Exception) {
                    // A failed local cleanup is harmless; the cache is opaque and
                    // will be replaced or wiped on the next authenticated refresh.
                }
            }
        }
    }

    private fun publishGroup(response: GroupResponse, message: String) {
        currentGroup = response
        state.update {
            it.copy(group = it.group.from(response).copy(isLoading = false, isMutating = false, message = message))
        }
    }

    private fun publishGroupRun(runId: String, runState: String) {
        state.update {
            it.copy(
                group = it.group.copy(
                    draft = "",
                    isMutating = false,
                    lastRun = GroupRunCard(runId, runState),
                    message = "Group turn $runState.",
                ),
            )
        }
    }

    private fun refreshGroupAfterConflict(group: GroupResponse) {
        state.update { it.copy(group = it.group.copy(isMutating = false, message = "Group changed elsewhere; loading its current membership…")) }
        viewModelScope.launch {
            try {
                val response = groups.loadGroup(group, System.currentTimeMillis())
                if (currentGroup?.groupId != response.groupId) return@launch
                currentGroup = response
                state.update {
                    it.copy(
                        group = it.group.from(response).copy(
                            message = "Group changed elsewhere; review the current membership before retrying.",
                        ),
                    )
                }
            } catch (_: AuthenticationCacheInvalidatedException) {
                showGroupAuthError("Encrypted device state was invalidated. Re-enroll this device.")
            } catch (_: HermesAuthExpiredException) {
                showGroupSessionExpired("Session expired before the current group could be loaded.")
            } catch (_: Exception) {
                showGroupError("Group changed elsewhere; refresh to load the current membership.")
            }
        }
    }

    private fun showGroupError(message: String) {
        state.update {
            it.copy(group = it.group.copy(isLoading = false, isMutating = false, message = message))
        }
    }

    private fun showGroupAuthError(message: String) {
        invalidateSensitiveState(message)
    }

    private fun showGroupSessionExpired(message: String) {
        state.update {
            it.copy(
                transport = TransportState.AUTH_EXPIRED,
                group = it.group.copy(isLoading = false, isMutating = false, message = message),
            )
        }
    }

    private fun invalidateSensitiveState(message: String) {
        // Stop the request factory from using stale in-memory bearer/device material while
        // the encrypted cache and Keystore are being wiped.  This is intentionally the
        // first operation so concurrently launched refreshes fail closed immediately.
        authSession.clearInMemory()
        draftPersistJob?.cancel()
        conversationLoadJob?.cancel()
        directRunJob?.cancel()
        draftEditGeneration += 1L
        conversationSelectionGeneration += 1L
        CacheWiper.wipeUnreadableCache(appContext)
        voiceRecorder.discard()
        pendingVoiceCapture?.file?.delete()
        pendingVoiceCapture = null
        currentGroup = null
        currentSettings = null
        pendingSettingsChallenge = null
        pendingSensitiveChanges = null
        state.update {
            it.copy(
                bots = emptyList(),
                botCards = emptyList(),
                selectedBot = null,
                selectedConversationId = null,
                conversations = emptyList(),
                conversationsStale = false,
                isLoadingConversations = false,
                transcript = emptyList(),
                directRun = DirectRunUiState(),
                directRuns = emptyList(),
                group = GroupUiState(),
                pendingApprovals = emptyList(),
                draft = "",
                selectedAttachmentCount = 0,
                selectedAttachmentIds = emptyList(),
                isAttachmentUploading = false,
                isRecording = false,
                pendingVoiceNoteDurationMillis = null,
                settings = SettingsUiState(),
                transport = TransportState.AUTH_EXPIRED,
                composerMessage = message,
            )
        }
        viewModelScope.launch { preferences.clearUnlock() }
    }

    private fun loadSettings(bot: BotId) {
        viewModelScope.launch {
            state.update { it.copy(settings = it.settings.copy(isLoading = true, message = null)) }
            try {
                val loaded = settings.load(bot, System.currentTimeMillis())
                if (state.value.selectedBot != bot) return@launch
                currentSettings = loaded.response
                pendingSettingsChallenge = null
                pendingSensitiveChanges = null
                state.update {
                    it.copy(
                        settings = it.settings.from(loaded.response),
                    )
                }
            } catch (_: HermesAuthExpiredException) {
                state.update {
                    it.copy(settings = it.settings.copy(isLoading = false, message = "Session expired; re-enroll this device."))
                }
            } catch (error: HermesApiException) {
                state.update {
                    it.copy(settings = it.settings.copy(isLoading = false, message = "Host settings could not be loaded (${error.statusCode})."))
                }
            } catch (_: java.io.IOException) {
                state.update {
                    it.copy(settings = it.settings.copy(isLoading = false, message = "Host settings are unavailable while the tunnel is offline."))
                }
            } catch (_: IllegalArgumentException) {
                state.update {
                    it.copy(settings = it.settings.copy(isLoading = false, message = "Host returned invalid settings metadata."))
                }
            }
        }
    }

    private fun saveSafeSettings() {
        val bot = state.value.selectedBot
        val current = currentSettings
        if (bot == null || current == null) {
            state.update { it.copy(settings = it.settings.copy(message = "Select an approved bot before editing host settings.")) }
            return
        }
        val draft = state.value.settings
        val changes = buildJsonObject {
            if (draft.draftDisplayName != current.displayName) put("display_name", draft.draftDisplayName)
            if (draft.draftTitle != current.title) put("title", draft.draftTitle)
            if (draft.draftAvatar != current.avatar) put("avatar", draft.draftAvatar)
            if (draft.draftNotificationsEnabled != draft.notificationsEnabled &&
                draft.draftNotificationsEnabled != null
            ) {
                val preferences = (current.notificationPreferences as? JsonObject).orEmpty()
                // The backend accepts a mapping and keeps any host-defined preference keys.
                put("notification_preferences", buildJsonObject {
                    preferences.forEach { (key, value) -> put(key, value) }
                    put("enabled", draft.draftNotificationsEnabled)
                })
            }
        }
        if (changes.isEmpty()) {
            state.update { it.copy(settings = it.settings.copy(message = "There are no safe settings changes to save.")) }
            return
        }
        viewModelScope.launch {
            state.update { it.copy(settings = it.settings.copy(isSaving = true, message = "Saving host settings…")) }
            try {
                val response = settings.updateSafe(bot, current, changes, System.currentTimeMillis())
                if (state.value.selectedBot != bot) return@launch
                currentSettings = response
                state.update { it.copy(settings = it.settings.from(response).copy(message = "Host settings saved.")) }
            } catch (error: HermesApiException) {
                if (error.statusCode == 409) {
                    refreshSettingsAfterConflict(bot)
                } else {
                    state.update {
                        it.copy(settings = it.settings.copy(isSaving = false, message = "Host settings were not saved (${error.statusCode}); retry explicitly."))
                    }
                }
            } catch (_: HermesAuthExpiredException) {
                state.update { it.copy(settings = it.settings.copy(isSaving = false, message = "Session expired before settings could be saved.")) }
            } catch (_: java.io.IOException) {
                state.update { it.copy(settings = it.settings.copy(isSaving = false, message = "Settings save paused; retry explicitly when the tunnel is available.")) }
            } catch (_: IllegalArgumentException) {
                state.update { it.copy(settings = it.settings.copy(isSaving = false, message = "Host settings were rejected as invalid.")) }
            }
        }
    }

    private fun prepareSensitiveSettings() {
        val bot = state.value.selectedBot
        val current = currentSettings
        if (bot == null || current == null) {
            state.update { it.copy(settings = it.settings.copy(message = "Select an approved bot before editing host settings.")) }
            return
        }
        val draft = state.value.settings
        if (draft.draftPersona == current.persona) {
            state.update { it.copy(settings = it.settings.copy(message = "There is no persona change to authenticate.")) }
            return
        }
        val changes = buildJsonObject { put("persona", draft.draftPersona) }
        viewModelScope.launch {
            state.update { it.copy(settings = it.settings.copy(isSaving = true, stepUpReady = false, message = "Preparing device authentication…")) }
            try {
                pendingSettingsChallenge = settings.createSensitiveChallenge(bot, current, changes)
                pendingSensitiveChanges = changes
                state.update {
                    it.copy(settings = it.settings.copy(isSaving = false, stepUpReady = true, message = "Authenticate with the device credential to save the persona."))
                }
            } catch (error: HermesApiException) {
                state.update { it.copy(settings = it.settings.copy(isSaving = false, message = "The host did not authorize this sensitive change (${error.statusCode}).")) }
            } catch (_: java.io.IOException) {
                state.update { it.copy(settings = it.settings.copy(isSaving = false, message = "Step-up preparation is unavailable while the tunnel is offline.")) }
            } catch (_: IllegalArgumentException) {
                state.update { it.copy(settings = it.settings.copy(isSaving = false, message = "The host returned an invalid step-up challenge.")) }
            }
        }
    }

    private fun saveSensitiveSettings() {
        val bot = state.value.selectedBot
        val current = currentSettings
        val challenge = pendingSettingsChallenge
        val changes = pendingSensitiveChanges
        if (bot == null || current == null || challenge == null || changes == null) {
            state.update { it.copy(settings = it.settings.copy(message = "Prepare the sensitive settings change before authenticating.")) }
            return
        }
        viewModelScope.launch {
            state.update { it.copy(settings = it.settings.copy(isSaving = true, stepUpReady = false, message = "Signing and saving sensitive settings…")) }
            try {
                val response = settings.updateSensitive(bot, current, changes, challenge, System.currentTimeMillis())
                if (state.value.selectedBot != bot) return@launch
                currentSettings = response
                pendingSettingsChallenge = null
                pendingSensitiveChanges = null
                state.update { it.copy(settings = it.settings.from(response).copy(message = "Sensitive host settings saved.")) }
            } catch (error: HermesApiException) {
                pendingSettingsChallenge = null
                pendingSensitiveChanges = null
                if (error.statusCode == 409) {
                    refreshSettingsAfterConflict(bot)
                } else {
                    state.update { it.copy(settings = it.settings.copy(isSaving = false, message = "Sensitive settings were not saved (${error.statusCode}); prepare a new step-up.")) }
                }
            } catch (_: HermesAuthExpiredException) {
                state.update { it.copy(settings = it.settings.copy(isSaving = false, message = "Session expired before sensitive settings could be saved.")) }
            } catch (_: java.io.IOException) {
                state.update { it.copy(settings = it.settings.copy(isSaving = false, message = "Sensitive settings save paused; prepare a new step-up to retry.")) }
            } catch (_: Exception) {
                state.update { it.copy(settings = it.settings.copy(isSaving = false, message = "Device authentication or the step-up signature failed.")) }
            }
        }
    }

    private fun refreshSettingsAfterConflict(bot: BotId) {
        viewModelScope.launch {
            try {
                val loaded = settings.load(bot, System.currentTimeMillis())
                if (state.value.selectedBot != bot) return@launch
                currentSettings = loaded.response
                pendingSettingsChallenge = null
                pendingSensitiveChanges = null
                state.update {
                    it.copy(
                        settings = it.settings.from(loaded.response).copy(
                            message = "Host settings changed elsewhere; review the fresh values before retrying.",
                        ),
                    )
                }
            } catch (_: Exception) {
                state.update {
                    it.copy(settings = it.settings.copy(isSaving = false, message = "Settings revision conflict; refresh to load the current host values."))
                }
            }
        }
    }

    private fun refreshApprovals() {
        viewModelScope.launch {
            try {
                val cards = approvals.listPending().approvals.map { approval ->
                    PendingApprovalCard(
                        approvalId = approval.approvalId,
                        summary = approval.summary,
                        expiresAtEpochMillis = (approval.expiresAtEpochSeconds * 1_000).toLong(),
                    )
                }
                state.update { it.copy(pendingApprovals = cards) }
            } catch (_: Exception) {
                // Approval cards are a secondary surface; sync remains usable if this read fails.
            }
        }
    }

    private fun denyApproval(approvalId: String) {
        viewModelScope.launch {
            try {
                approvals.deny(approvalId)
                refreshApprovals()
                state.update { it.copy(composerMessage = "Approval denied.") }
            } catch (error: Exception) {
                state.update { it.copy(composerMessage = "Approval could not be denied: ${error.message ?: "request failed"}.") }
            }
        }
    }

    private fun approveApproval(approvalId: String) {
        viewModelScope.launch {
            try {
                approvals.approveOnce(approvalId)
                refreshApprovals()
                state.update { it.copy(composerMessage = "Approval accepted once.") }
            } catch (error: Exception) {
                state.update { it.copy(composerMessage = "Approval was not accepted: ${error.message ?: "step-up failed"}.") }
            }
        }
    }

    private fun requestEditAsNew(operationId: String) {
        val card = state.value.transcript.firstOrNull { it.operationId == operationId }
        if (card == null || sendRecoveryAction(card.operationState) != SendRecoveryAction.EDIT_AS_NEW) {
            state.update { it.copy(composerMessage = "That send is not eligible for edit as new message.") }
            return
        }
        state.update { it.copy(editAsNewConfirmation = EditAsNewConfirmation(operationId)) }
    }

    private fun confirmEditAsNew() {
        val confirmation = state.value.editAsNewConfirmation ?: return
        val snapshot = state.value
        val bot = snapshot.selectedBot
        state.update { it.copy(editAsNewConfirmation = null) }
        if (bot == null) {
            state.update { it.copy(composerMessage = "Select an approved bot before editing this message.") }
            return
        }
        viewModelScope.launch {
            try {
                val original = repository.loadSendForEditAsNew(bot, confirmation.operationId)
                if (original == null || original.conversationId != state.value.selectedConversationId?.value) {
                    state.update {
                        it.copy(composerMessage = "The original send is no longer available in this conversation.")
                    }
                    return@launch
                }
                // Copying is deliberately the end of this action.  The next SendDraft creates a
                // fresh operation and idempotency key only after the user reviews the draft.
                setDraft(original.text)
                state.update {
                    it.copy(
                        selectedAttachmentIds = original.attachmentIds,
                        selectedAttachmentCount = original.attachmentIds.size,
                        composerMessage = "Copied as a new draft. Review it, then press Send message.",
                    )
                }
            } catch (_: UnreadableEncryptedValueException) {
                invalidateSensitiveState("Encrypted send state was invalidated. Re-enroll this device.")
            } catch (_: Exception) {
                state.update { it.copy(composerMessage = "The original send could not be opened for editing.") }
            }
        }
    }

    private fun sendDraft() {
        val snapshot = state.value
        when {
            snapshot.draft.isBlank() -> state.update { it.copy(composerMessage = "Write a message before sending.") }
            snapshot.selectedBot == null -> state.update { it.copy(composerMessage = "Select an approved bot before sending.") }
            snapshot.isLoadingConversations || snapshot.isAttachmentUploading ->
                state.update { it.copy(composerMessage = "Wait for the current conversation operation to finish.") }
            else -> viewModelScope.launch {
                val bot = snapshot.selectedBot ?: return@launch
                val text = snapshot.draft.trim()
                val prepared = try {
                    repository.prepareSendText(
                        target = bot,
                        conversationId = snapshot.selectedConversationId?.value,
                        text = text,
                        attachmentIds = snapshot.selectedAttachmentIds,
                        nowEpochMillis = System.currentTimeMillis(),
                    )
                } catch (_: AuthenticationCacheInvalidatedException) {
                    invalidateSensitiveState("Encrypted device state was invalidated. Re-enroll this device.")
                    return@launch
                } catch (_: UnreadableEncryptedValueException) {
                    invalidateSensitiveState("Encrypted device state was invalidated. Re-enroll this device.")
                    return@launch
                } catch (_: HermesAuthExpiredException) {
                    state.update { it.copy(transport = TransportState.AUTH_EXPIRED, composerMessage = "Session expired before sending; refresh and retry explicitly.") }
                    return@launch
                } catch (error: HermesApiException) {
                    state.update { it.copy(composerMessage = "Message could not be prepared (${error.statusCode}); retry explicitly.") }
                    return@launch
                } catch (_: java.io.IOException) {
                    state.update { it.copy(transport = TransportState.DISCONNECTED, composerMessage = "Hermes is unreachable; the message was not sent.") }
                    return@launch
                } catch (_: MobileOperationInProgressException) {
                    state.update {
                        it.copy(composerMessage = "A send for this conversation is still unresolved; retry it before sending another message.")
                    }
                    return@launch
                } catch (_: IllegalArgumentException) {
                    state.update { it.copy(composerMessage = "Message content or attachment references are invalid.") }
                    return@launch
                }
                val operationId = prepared.operation.operationId
                state.update {
                    it.copy(
                        selectedConversationId = ConversationId(prepared.conversationId),
                        composerMessage = "Sending securely…",
                        transcript = it.transcript + TranscriptCard(
                            messageId = "pending-$operationId",
                            authorLabel = "You",
                            role = TranscriptRole.USER,
                            parts = pendingMessageParts(text, prepared.attachmentIds),
                            delivery = DeliveryState.PENDING,
                            operationId = operationId,
                            operationState = MobileOperationStates.PENDING,
                        ),
                    )
                }
                val statusJob = launch { pollMessageStatus(bot, operationId) }
                trackMessageStatusJob(statusJob)
                try {
                    val result = repository.sendText(
                        target = bot,
                        conversationId = prepared.conversationId,
                        text = prepared.text,
                        attachmentIds = prepared.attachmentIds,
                        nowEpochMillis = System.currentTimeMillis(),
                        operationId = operationId,
                    )
                    statusJob.cancel()
                    if (state.value.selectedBot != bot) return@launch
                    draftPersistJob?.cancel()
                    draftEditGeneration += 1L
                    state.update {
                        it.copy(
                            selectedConversationId = ConversationId(result.conversationId),
                            draft = "",
                            selectedAttachmentCount = 0,
                            selectedAttachmentIds = emptyList(),
                            composerMessage = "Sent · ${result.state}",
                            directRun = DirectRunUiState(
                                runId = result.runId,
                                state = result.state.toRunState(),
                            ),
                            directRuns = visibleDirectRuns(
                                it.directRuns + DirectRunUiState(
                                    runId = result.runId,
                                    state = result.state.toRunState(),
                                ),
                            ),
                            transcript = it.transcript.map { card ->
                                if (card.operationId == operationId) {
                                    card.copy(
                                        delivery = DeliveryState.SENT,
                                        operationState = result.state,
                                        runId = result.runId,
                                    )
                                } else card
                            },
                        )
                    }
                    repository.saveDraft(
                        target = bot,
                        conversationId = prepared.conversationId,
                        text = "",
                        nowEpochMillis = System.currentTimeMillis(),
                    )
                    observeRun(bot, result.runId, operationId, result.conversationId)
                    loadConversation(bot, requestedConversationId = result.conversationId)
                } catch (_: HermesAuthExpiredException) {
                    statusJob.cancel()
                    if (state.value.selectedBot != bot) return@launch
                    state.update {
                        it.copy(
                            transport = TransportState.AUTH_EXPIRED,
                            composerMessage = "Session expired before sending; retry explicitly after refresh.",
                            transcript = it.transcript.map { card ->
                                if (card.operationId == operationId) card.copy(
                                    delivery = DeliveryState.FAILED,
                                    operationState = MobileOperationStates.UNCERTAIN,
                                ) else card
                            },
                        )
                    }
                    checkMessageStatus(bot, operationId)
                } catch (_: AuthenticationCacheInvalidatedException) {
                    statusJob.cancel()
                    invalidateSensitiveState("Encrypted device state was invalidated. Re-enroll this device.")
                } catch (_: UnreadableEncryptedValueException) {
                    statusJob.cancel()
                    invalidateSensitiveState("Encrypted device state was invalidated. Re-enroll this device.")
                } catch (error: HermesApiException) {
                    statusJob.cancel()
                    if (state.value.selectedBot != bot) return@launch
                    val operationState = classifyMobileSendFailure(error.statusCode, error.errorCode)
                    val message = when {
                        error.statusCode == 401 ->
                            "Authentication expired before Hermes accepted this message; restore authentication, then retry the original."
                        operationState == MobileOperationStates.CONFLICT ->
                            "This idempotency key conflicts with another request. The original send is blocked; choose Edit as new message."
                        operationState == MobileOperationStates.REJECTED ->
                            "Hermes rejected this message (${error.statusCode}). Choose Edit as new message to author a fresh send."
                        operationState == MobileOperationStates.INDETERMINATE ->
                            "The send outcome is indeterminate. Refresh its status, or choose Edit as new message."
                        else ->
                            "Message outcome is uncertain (${error.statusCode}); check status before retrying the original."
                    }
                    state.update {
                        it.copy(
                            transport = if (error.statusCode == 401) {
                                TransportState.AUTH_EXPIRED
                            } else {
                                it.transport
                            },
                            composerMessage = message,
                            transcript = it.transcript.map { card ->
                                if (card.operationId == operationId) card.copy(
                                    delivery = DeliveryState.FAILED,
                                    operationState = operationState,
                                ) else card
                            },
                        )
                    }
                    if (operationState == MobileOperationStates.UNCERTAIN ||
                        operationState == MobileOperationStates.INDETERMINATE
                    ) {
                        checkMessageStatus(bot, operationId)
                    }
                } catch (_: java.io.IOException) {
                    statusJob.cancel()
                    if (state.value.selectedBot != bot) return@launch
                    state.update {
                        it.copy(
                            transport = TransportState.DISCONNECTED,
                            composerMessage = "Message could not reach Hermes; the idempotency record was retained.",
                            transcript = it.transcript.map { card ->
                                if (card.operationId == operationId) card.copy(
                                    delivery = DeliveryState.FAILED,
                                    operationState = MobileOperationStates.UNCERTAIN,
                                ) else card
                            },
                        )
                    }
                    checkMessageStatus(bot, operationId)
                } catch (_: IllegalArgumentException) {
                    statusJob.cancel()
                    if (state.value.selectedBot != bot) return@launch
                    state.update {
                        it.copy(
                            composerMessage = "The original send operation is no longer retryable; compose a new message.",
                            transcript = it.transcript.map { card ->
                                if (card.operationId == operationId) card.copy(
                                    delivery = DeliveryState.FAILED,
                                    operationState = card.operationState ?: MobileOperationStates.REJECTED,
                                ) else card
                            },
                        )
                    }
                }
            }
        }
    }

    private fun retrySend(operationId: String) {
        val snapshot = state.value
        val bot = snapshot.selectedBot ?: return
        val card = snapshot.transcript.firstOrNull { it.operationId == operationId }
        if (card == null || card.delivery != DeliveryState.FAILED) {
            state.update { it.copy(composerMessage = "That send is not waiting for a retry.") }
            return
        }
        when (sendRecoveryAction(card.operationState)) {
            SendRecoveryAction.EDIT_AS_NEW -> {
                state.update {
                    it.copy(composerMessage = "This send is blocked from replay; choose Edit as new message.")
                }
                return
            }
            SendRecoveryAction.NONE -> if (card.operationState != null) {
                state.update { it.copy(composerMessage = "That send cannot be retried from this state.") }
                return
            }
            SendRecoveryAction.RETRY_ORIGINAL -> Unit
        }
        viewModelScope.launch {
            // A retry is allowed to replay only after this read-only lookup succeeds.  A
            // transient status-read failure is not equivalent to an unknown host result.
            val status = try {
                repository.messageStatus(bot, operationId, System.currentTimeMillis())
            } catch (_: HermesAuthExpiredException) {
                state.update {
                    it.copy(
                        transport = TransportState.AUTH_EXPIRED,
                        composerMessage = "Session expired; restore authentication before retrying this send.",
                    )
                }
                return@launch
            } catch (_: AuthenticationCacheInvalidatedException) {
                invalidateSensitiveState("Encrypted device state was invalidated. Re-enroll this device.")
                return@launch
            } catch (_: UnreadableEncryptedValueException) {
                invalidateSensitiveState("Encrypted device state was invalidated. Re-enroll this device.")
                return@launch
            } catch (error: HermesApiException) {
                state.update {
                    it.copy(
                        transport = if (error.statusCode == 401 || error.statusCode == 403) {
                            TransportState.AUTH_EXPIRED
                        } else {
                            it.transport
                        },
                        composerMessage = "Could not check the original send (${error.statusCode}); retry the status check before sending again.",
                    )
                }
                return@launch
            } catch (_: java.io.IOException) {
                state.update {
                    it.copy(
                        transport = TransportState.DISCONNECTED,
                        composerMessage = "Could not check the original send; reconnect before retrying it.",
                    )
                }
                return@launch
            } catch (_: Exception) {
                state.update {
                    it.copy(composerMessage = "Could not check the original send; retry the status check before sending again.")
                }
                return@launch
            }
            if (status == null) {
                state.update {
                    it.copy(composerMessage = "That send is no longer available locally; reload the conversation before retrying.")
                }
                return@launch
            }
            val observed = status.run
            if (observed != null) {
                publishDirectRun(bot, observed, operationId)
                if (observed.state.lowercase() in TERMINAL_RUN_STATES) {
                    val outcomeMessage = if (observed.state.equals("indeterminate", ignoreCase = true)) {
                        "The host could not confirm this send; it was not sent twice. Choose Edit as new message if you want a fresh draft."
                    } else {
                        "The host already recorded this send as ${observed.state}; it was not sent twice."
                    }
                    state.update {
                        it.copy(
                            composerMessage = outcomeMessage,
                            transcript = it.transcript.map { item ->
                                if (item.operationId == operationId) item.copy(
                                    delivery = if (observed.state.equals("completed", ignoreCase = true)) {
                                        DeliveryState.SENT
                                    } else {
                                        DeliveryState.FAILED
                                    },
                                    operationState = observed.state,
                                    runId = observed.runId,
                                ) else item
                            },
                        )
                    }
                    if (observed.state == "completed") loadConversation(bot, requestedConversationId = observed.conversationId)
                    return@launch
                }
                // A run already linked to the original key is authoritative even when it is
                // still queued or thinking.  Never issue a second POST while it is active.
                state.update {
                    it.copy(
                        composerMessage = "The host already has this send in progress; it was not sent twice.",
                        transcript = it.transcript.map { item ->
                            if (item.operationId == operationId) {
                                item.copy(
                                    delivery = DeliveryState.PENDING,
                                    runState = observed.state.toRunState(),
                                    operationState = observed.state,
                                    runId = observed.runId,
                                )
                            } else item
                        },
                    )
                }
                observeRun(bot, observed.runId, operationId)
                return@launch
            }
            state.update {
                it.copy(
                    composerMessage = "Retrying the original send…",
                    transcript = it.transcript.map { item ->
                        if (item.operationId == operationId) item.copy(
                            delivery = DeliveryState.PENDING,
                            operationState = MobileOperationStates.SENDING,
                        ) else item
                    },
                )
            }
            try {
                val result = repository.retryText(bot, operationId, System.currentTimeMillis())
                if (state.value.selectedBot != bot) return@launch
                state.update {
                    it.copy(
                        composerMessage = "Sent · ${result.state}",
                        directRun = DirectRunUiState(result.runId, result.state.toRunState()),
                        directRuns = visibleDirectRuns(
                            it.directRuns + DirectRunUiState(result.runId, result.state.toRunState()),
                        ),
                        transcript = it.transcript.map { item ->
                            if (item.operationId == operationId) item.copy(
                                delivery = DeliveryState.SENT,
                                operationState = result.state,
                                runId = result.runId,
                            ) else item
                        },
                    )
                }
                observeRun(bot, result.runId, operationId)
                loadConversation(bot, requestedConversationId = result.conversationId)
            } catch (error: HermesApiException) {
                val operationState = classifyMobileSendFailure(error.statusCode, error.errorCode)
                val message = when {
                    error.statusCode == 401 ->
                        "Authentication expired before Hermes accepted this retry; restore authentication, then retry the original."
                    operationState == MobileOperationStates.CONFLICT ->
                        "Retry hit an idempotency conflict; the original is blocked. Choose Edit as new message."
                    operationState == MobileOperationStates.REJECTED ->
                        "The host rejected this retry (${error.statusCode}); choose Edit as new message."
                    operationState == MobileOperationStates.INDETERMINATE ->
                        "Retry outcome is indeterminate; refresh status or choose Edit as new message."
                    else ->
                        "Retry failed (${error.statusCode}); inspect the original operation before trying again."
                }
                state.update {
                    it.copy(
                        transport = if (error.statusCode == 401) {
                            TransportState.AUTH_EXPIRED
                        } else {
                            it.transport
                        },
                        composerMessage = message,
                        transcript = it.transcript.map { item ->
                            if (item.operationId == operationId) item.copy(
                                delivery = DeliveryState.FAILED,
                                operationState = operationState,
                            ) else item
                        },
                    )
                }
            } catch (_: UnreadableEncryptedValueException) {
                invalidateSensitiveState("Encrypted device state was invalidated. Re-enroll this device.")
            } catch (_: Exception) {
                state.update {
                    it.copy(
                        composerMessage = "Retry could not be confirmed; inspect the send status before trying again.",
                        transcript = it.transcript.map { item ->
                            if (item.operationId == operationId) item.copy(
                                delivery = DeliveryState.FAILED,
                                operationState = item.operationState ?: MobileOperationStates.UNCERTAIN,
                            ) else item
                        },
                    )
                }
            }
        }
    }

    private suspend fun pollMessageStatus(bot: BotId, operationId: String) {
        var nextDelayMillis = 3_000L
        while (
            currentCoroutineContext().isActive &&
                state.value.selectedBot == bot &&
                state.value.section == HomeSection.CHAT
        ) {
            try {
                val status = repository.messageStatus(bot, operationId, System.currentTimeMillis())
                nextDelayMillis = 3_000L
                val run = status?.run
                if (run != null) {
                    publishDirectRun(bot, run, operationId)
                    if (run.state.lowercase() in TERMINAL_RUN_STATES) return
                }
            } catch (_: HermesAuthExpiredException) {
                state.update {
                    it.copy(
                        transport = TransportState.AUTH_EXPIRED,
                        composerMessage = "Session expired; restore authentication before checking this send.",
                    )
                }
                return
            } catch (_: AuthenticationCacheInvalidatedException) {
                invalidateSensitiveState("Encrypted device state was invalidated. Re-enroll this device.")
                return
            } catch (_: UnreadableEncryptedValueException) {
                invalidateSensitiveState("Encrypted device state was invalidated. Re-enroll this device.")
                return
            } catch (error: HermesApiException) {
                if (error.statusCode == 401 || error.statusCode == 403) {
                    state.update {
                        it.copy(
                            transport = TransportState.AUTH_EXPIRED,
                            composerMessage = "Authentication is required before checking this send.",
                        )
                    }
                    return
                }
                nextDelayMillis = (nextDelayMillis * 2).coerceAtMost(30_000L)
            } catch (_: java.io.IOException) {
                nextDelayMillis = (nextDelayMillis * 2).coerceAtMost(30_000L)
            } catch (_: Exception) {
                nextDelayMillis = (nextDelayMillis * 2).coerceAtMost(30_000L)
            }
            delay(nextDelayMillis)
        }
    }

    private fun checkMessageStatus(bot: BotId, operationId: String) {
        val statusJob = viewModelScope.launch {
            delay(250)
            try {
                repository.messageStatus(bot, operationId, System.currentTimeMillis())
                    ?.run
                    ?.let { publishDirectRun(bot, it, operationId) }
            } catch (_: AuthenticationCacheInvalidatedException) {
                invalidateSensitiveState("Encrypted device state was invalidated. Re-enroll this device.")
            } catch (_: UnreadableEncryptedValueException) {
                invalidateSensitiveState("Encrypted device state was invalidated. Re-enroll this device.")
            } catch (_: Exception) {
                // A status read is best-effort after a failed send; the durable operation remains
                // available for the next explicit retry or foreground refresh.
            }
        }
        trackMessageStatusJob(statusJob)
    }

    private fun trackMessageStatusJob(job: Job) {
        messageStatusJobs.add(job)
        job.invokeOnCompletion { messageStatusJobs.remove(job) }
        if (!job.isActive) messageStatusJobs.remove(job)
    }

    private fun cancelMessageStatusJobs() {
        val jobs = synchronized(messageStatusJobs) { messageStatusJobs.toList() }
        jobs.forEach { it.cancel() }
        messageStatusJobs.clear()
    }

    /**
     * Room is the live projection while the conversation is visible.  The host GET remains a
     * fallback for a missing/stale projection, and an SSE close only causes its own reconnect
     * loop; neither transport event cancels this observer.
     */
    private fun observeRun(
        bot: BotId,
        runId: String? = null,
        operationId: String? = null,
        conversationId: String? = state.value.selectedConversationId?.value,
    ) {
        directRunJob?.cancel()
        directRunJob = viewModelScope.launch {
            val selectedConversationId = conversationId ?: return@launch
            val projectedJob = launch {
                try {
                    repository.observeProjectedRuns(bot, selectedConversationId).collect { runs ->
                        if (state.value.selectedBot == bot &&
                            state.value.section == HomeSection.CHAT &&
                            state.value.selectedConversationId?.value == selectedConversationId
                        ) {
                            publishProjectedRuns(bot, runs, runId)
                        }
                    }
                } catch (cancelled: CancellationException) {
                    throw cancelled
                } catch (_: Exception) {
                    // API polling below continues when Room is temporarily unavailable.
                }
            }
            val pollingJob = launch {
                val pollingRunIds = linkedSetOf<String>().apply {
                    runId?.let(::add)
                }
                var nextDelayMillis = 2_000L
                while (
                    currentCoroutineContext().isActive &&
                        state.value.selectedBot == bot &&
                        state.value.section == HomeSection.CHAT &&
                        state.value.selectedConversationId?.value == selectedConversationId
                ) {
                    // Room is authoritative, but every projected nonterminal run remains a
                    // fallback GET target. This also discovers runs added after this observer
                    // started without conflating their IDs or mutating another card.
                    pollingRunIds += state.value.directRuns.mapNotNull(DirectRunUiState::runId)
                    if (pollingRunIds.isEmpty()) {
                        nextDelayMillis = 30_000L
                        delay(nextDelayMillis)
                        continue
                    }
                    var hadFailure = false
                    for (observedRunId in pollingRunIds.toList()) {
                        try {
                            val run = repository.getRun(bot, observedRunId, System.currentTimeMillis())
                            publishDirectRun(
                                bot,
                                run,
                                operationId = operationId?.takeIf { observedRunId == runId },
                            )
                            if (run.state.lowercase() in TERMINAL_RUN_STATES) {
                                pollingRunIds.remove(observedRunId)
                            }
                        } catch (_: HermesAuthExpiredException) {
                            state.update {
                                it.copy(
                                    transport = TransportState.AUTH_EXPIRED,
                                    composerMessage = "Run status needs a refreshed session.",
                                )
                            }
                            return@launch
                        } catch (cancelled: CancellationException) {
                            throw cancelled
                        } catch (_: Exception) {
                            // Keep the last durable Room state visible and retry while the tunnel recovers.
                            hadFailure = true
                        }
                    }
                    nextDelayMillis = if (hadFailure) {
                        (nextDelayMillis * 2).coerceAtMost(30_000L)
                    } else {
                        2_000L
                    }
                    delay(nextDelayMillis)
                }
            }
            pollingJob.join()
            projectedJob.join()
        }
    }

    private fun refreshRun(runId: String) {
        val bot = state.value.selectedBot ?: return
        observeRun(bot, runId)
    }

    private fun cancelRun(runId: String) {
        val bot = state.value.selectedBot ?: return
        val selectedRun = state.value.directRuns.firstOrNull { it.runId == runId }
            ?: state.value.directRun.takeIf { it.runId == runId }
        if (selectedRun == null || selectedRun.isCancelling) return
        viewModelScope.launch {
            state.update {
                it.copy(
                    directRun = if (it.directRun.runId == runId) {
                        it.directRun.copy(isCancelling = true, message = "Requesting stop…")
                    } else it.directRun,
                    directRuns = it.directRuns.map { run ->
                        if (run.runId == runId) run.copy(isCancelling = true, message = "Requesting stop…") else run
                    },
                )
            }
            try {
                val run = repository.cancelRun(bot, runId, System.currentTimeMillis())
                publishDirectRun(bot, run)
                state.update { it.copy(composerMessage = "Stop recorded as ${run.state}.") }
                observeRun(bot, runId, conversationId = state.value.selectedConversationId?.value)
            } catch (_: MobileOperationInProgressException) {
                // A second tap can arrive before the first coroutine publishes its isCancelling
                // state. The durable operation gate rejected the duplicate; keep the existing
                // stop attempt visible instead of labelling it an indeterminate failure.
                state.update {
                    it.copy(
                        composerMessage = "A stop request for this run is already in progress; refresh its status.",
                        directRun = if (it.directRun.runId == runId) {
                            it.directRun.copy(isCancelling = false)
                        } else it.directRun,
                        directRuns = it.directRuns.map { run ->
                            if (run.runId == runId) run.copy(isCancelling = false) else run
                        },
                    )
                }
            } catch (error: HermesApiException) {
                state.update {
                    it.copy(
                        directRun = if (it.directRun.runId == runId) {
                            it.directRun.copy(isCancelling = false, message = "Stop could not be confirmed.")
                        } else it.directRun,
                        directRuns = it.directRuns.map { run ->
                            if (run.runId == runId) run.copy(isCancelling = false, message = "Stop could not be confirmed.") else run
                        },
                        composerMessage = "Stop request failed (${error.statusCode}); refresh the run before retrying.",
                    )
                }
            } catch (_: HermesAuthExpiredException) {
                state.update {
                    it.copy(
                        transport = TransportState.AUTH_EXPIRED,
                        directRun = if (it.directRun.runId == runId) {
                            it.directRun.copy(isCancelling = false, message = "Session expired before the stop could be confirmed.")
                        } else it.directRun,
                        directRuns = it.directRuns.map { run ->
                            if (run.runId == runId) run.copy(isCancelling = false, message = "Session expired before the stop could be confirmed.") else run
                        },
                        composerMessage = "Session expired; restore authentication before retrying the stop.",
                    )
                }
            } catch (_: AuthenticationCacheInvalidatedException) {
                invalidateSensitiveState("Encrypted device state was invalidated. Re-enroll this device.")
            } catch (_: UnreadableEncryptedValueException) {
                invalidateSensitiveState("Encrypted device state was invalidated. Re-enroll this device.")
            } catch (_: Exception) {
                state.update {
                    it.copy(
                        directRun = if (it.directRun.runId == runId) {
                            it.directRun.copy(isCancelling = false, message = "Stop outcome is uncertain.")
                        } else it.directRun,
                        directRuns = it.directRuns.map { run ->
                            if (run.runId == runId) run.copy(isCancelling = false, message = "Stop outcome is uncertain.") else run
                        },
                        composerMessage = "Stop could not be confirmed; refresh the run before retrying.",
                    )
                }
            }
        }
    }

    private fun publishProjectedRuns(
        bot: BotId,
        runs: List<RunWire>,
        preferredRunId: String?,
    ) {
        if (state.value.selectedBot != bot) return
        val selectedConversationId = state.value.selectedConversationId?.value ?: return
        val projected = runs.filter { it.conversationId == selectedConversationId }
        val projectedUi = projected.map { run ->
            DirectRunUiState(
                runId = run.runId,
                state = run.state.toRunState(),
                cancelRequested = run.cancelRequested,
                completedExternalSideEffectsNotUndone = run.completedExternalSideEffectsNotUndone,
                message = run.error,
            )
        }
        val preferred = preferredRunId ?: state.value.directRun.runId
        val selected = projectedUi.firstOrNull { it.runId == preferred }
            ?: projectedUi.firstOrNull()
        state.update {
            if (it.selectedBot != bot || it.selectedConversationId?.value != selectedConversationId) return@update it
            it.copy(
                directRun = selected ?: it.directRun,
                directRuns = visibleDirectRuns(projectedUi),
            )
        }
        // Reuse the exact run-ID card transition so Room updates also settle the matching
        // transcript card; no conversation-wide or text-based card updates are allowed.
        projected.forEach { run -> publishDirectRun(bot, run) }
        selected?.let { preferred ->
            state.update {
                if (it.selectedBot == bot && it.selectedConversationId?.value == selectedConversationId) {
                    it.copy(directRun = preferred)
                } else it
            }
        }
    }

    private fun publishDirectRun(bot: BotId, run: RunWire, operationId: String? = null) {
        if (state.value.selectedBot != bot ||
            (run.conversationId != null && run.conversationId != state.value.selectedConversationId?.value)
        ) return
        val runState = run.state.toRunState()
        val terminal = run.state.lowercase() in TERMINAL_RUN_STATES
        val keepsOperation = run.state.equals(MobileOperationStates.INDETERMINATE, ignoreCase = true)
        state.update {
            val directRun = DirectRunUiState(
                runId = run.runId,
                state = runState,
                cancelRequested = run.cancelRequested,
                completedExternalSideEffectsNotUndone = run.completedExternalSideEffectsNotUndone,
                isCancelling = false,
                message = run.error,
            )
            val matchingCard: (TranscriptCard) -> Boolean = { card ->
                card.runId == run.runId || (operationId != null && card.operationId == operationId)
            }
            it.copy(
                directRun = directRun,
                directRuns = visibleDirectRuns(
                    it.directRuns.filterNot { item -> item.runId == run.runId } + directRun,
                ),
                transcript = it.transcript.map { card ->
                    if (matchingCard(card)) {
                        card.copy(
                            delivery = when {
                                run.state.equals("completed", ignoreCase = true) -> DeliveryState.SENT
                                terminal -> DeliveryState.FAILED
                                else -> card.delivery
                            },
                            runState = runState,
                            operationId = if (terminal && !keepsOperation) null else card.operationId,
                            operationState = run.state,
                            runId = run.runId,
                        )
                    } else card
                },
            )
        }
    }

    private fun uploadAttachment(uri: Uri) {
        val bot = state.value.selectedBot
        if (bot == null) {
            state.update { it.copy(composerMessage = "Select an approved bot before attaching a file.") }
            return
        }
        viewModelScope.launch {
            state.update { it.copy(isAttachmentUploading = true, composerMessage = "Encrypting and uploading attachment…") }
            try {
                val conversation = state.value.selectedConversationId?.value
                    ?: repository.ensureCanonicalConversation(bot, System.currentTimeMillis()).conversationId
                val result = attachmentUploads.uploadUri(
                    context = appContext,
                    bot = com.hermes.mobile.network.AttachmentBotId(bot.instanceId, bot.opaqueProfileId),
                    conversationId = conversation,
                    uri = uri,
                    nowEpochMillis = System.currentTimeMillis(),
                )
                state.update {
                    it.copy(
                        selectedConversationId = ConversationId(conversation),
                        selectedAttachmentIds = it.selectedAttachmentIds + result.attachmentId,
                        selectedAttachmentCount = it.selectedAttachmentCount + 1,
                        composerMessage = "Attachment ready; send it with your next message.",
                    )
                }
            } catch (_: HermesAuthExpiredException) {
                state.update { it.copy(transport = TransportState.AUTH_EXPIRED, composerMessage = "Session expired before uploading the attachment.") }
            } catch (error: HermesApiException) {
                state.update { it.copy(composerMessage = "Attachment upload failed (${error.statusCode}); retry explicitly to resume.") }
            } catch (_: java.io.IOException) {
                state.update { it.copy(transport = TransportState.DISCONNECTED, composerMessage = "Attachment upload paused; retry to resume the encrypted upload.") }
            } catch (_: IllegalArgumentException) {
                state.update { it.copy(composerMessage = "Attachment is unsupported or exceeds the 25 MB limit.") }
            } finally {
                state.update { it.copy(isAttachmentUploading = false) }
            }
        }
    }

    private fun clearAttachments() {
        if (state.value.selectedAttachmentIds.isEmpty()) return
        state.update {
            it.copy(
                selectedAttachmentIds = emptyList(),
                selectedAttachmentCount = 0,
                composerMessage = "Attachment references cleared from this draft.",
            )
        }
    }

    private fun toggleVoiceNote() {
        if (!state.value.isRecording && state.value.selectedBot == null) {
            state.update { it.copy(composerMessage = "Select an approved bot before recording a voice note.") }
            return
        }
        if (!state.value.isRecording) {
            runCatching { voiceRecorder.start() }
                .onSuccess {
                    state.update {
                        it.copy(
                            isRecording = true,
                            composerMessage = "Recording AAC-LC voice note… tap again to review.",
                        )
                    }
                }
                .onFailure { error ->
                    state.update { it.copy(composerMessage = "Voice recording could not start: ${error.message ?: "device error"}.") }
                }
            return
        }
        val capture = runCatching { voiceRecorder.stop() }.getOrElse {
            state.update { it.copy(isRecording = false, composerMessage = "Voice recording could not be finalized.") }
            return
        }
        if (state.value.selectedBot == null) {
            capture.file.delete()
            state.update { it.copy(isRecording = false, composerMessage = "Select an approved bot before recording a voice note.") }
            return
        }
        pendingVoiceCapture?.file?.delete()
        pendingVoiceCapture = capture
        state.update {
            it.copy(
                isRecording = false,
                pendingVoiceNoteDurationMillis = capture.durationMillis,
                composerMessage = "Voice note ready for review; upload it or discard it.",
            )
        }
    }

    private fun uploadPendingVoiceNote() {
        val capture = pendingVoiceCapture ?: run {
            state.update { it.copy(composerMessage = "Record a voice note before uploading it.") }
            return
        }
        val bot = state.value.selectedBot ?: run {
            capture.file.delete()
            pendingVoiceCapture = null
            state.update { it.copy(pendingVoiceNoteDurationMillis = null, composerMessage = "Select an approved bot before uploading the voice note.") }
            return
        }
        viewModelScope.launch {
            state.update { it.copy(isAttachmentUploading = true, composerMessage = "Encrypting and uploading voice note…") }
            try {
                val conversation = state.value.selectedConversationId?.value
                    ?: repository.ensureCanonicalConversation(bot, System.currentTimeMillis()).conversationId
                val result = attachmentUploads.uploadFile(
                    bot = com.hermes.mobile.network.AttachmentBotId(bot.instanceId, bot.opaqueProfileId),
                    conversationId = conversation,
                    file = capture.file,
                    fileName = "voice-note-${capture.durationMillis}.m4a",
                    mimeType = capture.mimeType,
                    nowEpochMillis = System.currentTimeMillis(),
                )
                capture.file.delete()
                pendingVoiceCapture = null
                state.update {
                    it.copy(
                        selectedConversationId = ConversationId(conversation),
                        selectedAttachmentIds = it.selectedAttachmentIds + result.attachmentId,
                        selectedAttachmentCount = it.selectedAttachmentCount + 1,
                        pendingVoiceNoteDurationMillis = null,
                        composerMessage = "Voice note ready; send it with your next message.",
                    )
                }
            } catch (_: HermesAuthExpiredException) {
                state.update { it.copy(transport = TransportState.AUTH_EXPIRED, composerMessage = "Session expired before uploading the voice note.") }
            } catch (error: HermesApiException) {
                state.update { it.copy(composerMessage = "Voice note upload failed (${error.statusCode}); retry explicitly to resume.") }
            } catch (_: java.io.IOException) {
                state.update { it.copy(transport = TransportState.DISCONNECTED, composerMessage = "Voice note upload paused; retry to resume the encrypted upload.") }
            } catch (_: IllegalArgumentException) {
                state.update { it.copy(composerMessage = "Voice note is unsupported or exceeds the ten-minute limit.") }
            } finally {
                // The original recorder output is never needed after it has been staged. The
                // encrypted staged upload remains available for an explicit retry.
                capture.file.delete()
                state.update { it.copy(isAttachmentUploading = false) }
            }
        }
    }

    private fun discardPendingVoiceNote() {
        pendingVoiceCapture?.file?.delete()
        pendingVoiceCapture = null
        state.update {
            it.copy(
                pendingVoiceNoteDurationMillis = null,
                composerMessage = "Voice note discarded.",
            )
        }
    }

    private fun refreshCachedBots() {
        viewModelScope.launch {
            val cards = try {
                dao.listSyncTargets().mapNotNull { target ->
                    runCatching {
                        val bot = BotId(target.instanceId, target.opaqueProfileId)
                        BotCardState(
                            bot = bot,
                            displayName = "Profile ${presentationTail(target.opaqueProfileId)}",
                            originLabel = "Instance ${presentationTail(target.instanceId)}",
                            transport = TransportState.STALE,
                        )
                    }.getOrNull()
                }
            } catch (_: Exception) {
                emptyList()
            }
            state.update { current ->
                val availableBots = cards.map { it.bot }.toSet()
                current.copy(
                    bots = cards.map { it.bot },
                    botCards = cards,
                    selectedBot = current.selectedBot?.takeIf { selected -> cards.any { it.bot == selected } },
                    group = current.group.copy(
                        selectedBotIds = current.group.selectedBotIds.filter { bot -> bot in availableBots },
                    ),
                )
            }
        }
    }

    private fun presentationTail(value: String): String =
        value.takeLast(6).ifBlank { "unknown" }
}

private fun com.hermes.mobile.network.MobileProfileWire.toContractBot(): BotId =
    BotId(bot.instanceId, bot.opaqueProfileId)

private fun GroupUiState.from(response: GroupResponse): GroupUiState = copy(
    groupId = response.groupId,
    instanceId = response.instanceId,
    coordinatorMemberId = response.coordinatorMemberId,
    members = response.members.map { member ->
        GroupMemberCard(
            memberId = member.memberId,
            label = member.label,
            bot = BotId(member.bot.instanceId, member.bot.opaqueProfileId),
        )
    },
    lifecycle = when (response.state) {
        "active" -> GroupLifecycle.ACTIVE
        "stopped" -> GroupLifecycle.STOPPED
        else -> error("unsupported group state")
    },
    authorityEpoch = response.authorityEpoch,
    activeTurnId = response.activeTurnId,
    isLoading = false,
    isMutating = false,
)

private fun SettingsUiState.from(response: SettingsResponse): SettingsUiState = copy(
    isLoading = false,
    isSaving = false,
    profileId = response.profileId,
    revision = response.revision,
    displayName = response.displayName,
    title = response.title,
    avatar = response.avatar,
    notificationsEnabled = response.notificationPreferences.preferenceBoolean("enabled"),
    persona = response.persona,
    draftDisplayName = response.displayName,
    draftTitle = response.title,
    draftAvatar = response.avatar,
    draftNotificationsEnabled = response.notificationPreferences.preferenceBoolean("enabled"),
    draftPersona = response.persona,
    stepUpReady = false,
)

private fun JsonElement.preferenceBoolean(key: String): Boolean? =
    (this as? JsonObject)?.get(key)?.let { value ->
        (value as? JsonPrimitive)?.booleanOrNull
    }

private fun String.toRunState(): RunState = when (lowercase()) {
    "queued" -> RunState.QUEUED
    "thinking" -> RunState.THINKING
    "tool_running", "toolrunning", "tool-running" -> RunState.TOOL_RUNNING
    "waiting_for_user", "waitingforuser", "waiting-for-user" -> RunState.WAITING_FOR_USER
    "approval_required", "approvalrequired", "approval-required" -> RunState.APPROVAL_REQUIRED
    "completed" -> RunState.COMPLETED
    "failed" -> RunState.FAILED
    "cancelled", "canceled" -> RunState.CANCELLED
    "indeterminate" -> RunState.INDETERMINATE
    else -> RunState.INDETERMINATE
}

private val TERMINAL_RUN_STATES = setOf("completed", "failed", "cancelled", "canceled", "indeterminate")

private fun visibleDirectRuns(runs: List<DirectRunUiState>): List<DirectRunUiState> =
    runs.filter { run ->
        run.runId != null && run.state !in setOf(
            RunState.COMPLETED,
            RunState.FAILED,
            RunState.CANCELLED,
        )
    }.distinctBy(DirectRunUiState::runId)

private fun operationIdFromLocalMessageId(messageId: String): String? =
    messageId.takeIf { it.startsWith("local-") }
        ?.removePrefix("local-")
        ?.takeIf(String::isNotBlank)

private fun RunWire.toDirectRunUiState(): DirectRunUiState = DirectRunUiState(
    runId = runId,
    state = state.toRunState(),
    cancelRequested = cancelRequested,
    completedExternalSideEffectsNotUndone = completedExternalSideEffectsNotUndone,
    message = error,
)
