package com.hermes.mobile.ui

import android.Manifest
import android.app.Activity
import android.app.KeyguardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.view.WindowManager
import android.widget.Toast
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.browser.customtabs.CustomTabsIntent
import androidx.core.content.ContextCompat
import androidx.activity.viewModels
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AttachFile
import androidx.compose.material.icons.outlined.ChatBubbleOutline
import androidx.compose.material.icons.outlined.Close
import androidx.compose.material.icons.outlined.Group
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.Mic
import androidx.compose.material.icons.outlined.Refresh
import androidx.compose.material.icons.outlined.Send
import androidx.compose.material.icons.outlined.Settings
import androidx.compose.material.icons.outlined.Stop
import androidx.compose.material.icons.outlined.SmartToy
import androidx.compose.material3.AssistChip
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.Checkbox
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import com.hermes.mobile.contract.AttentionState
import com.hermes.mobile.contract.InboundIntentDecision
import com.hermes.mobile.contract.InboundIntentPayload
import com.hermes.mobile.contract.InboundIntentPolicy
import com.hermes.mobile.contract.LinkPolicy
import com.hermes.mobile.contract.MessagePart
import com.hermes.mobile.contract.RejectionReason
import com.hermes.mobile.contract.RunState
import com.hermes.mobile.contract.TransportState
import com.hermes.mobile.data.AppPreferencesRepository
import com.hermes.mobile.sync.SyncWorkScheduler
import com.hermes.mobile.ui.theme.HermesTheme
import dagger.hilt.android.AndroidEntryPoint
import javax.inject.Inject
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch

@AndroidEntryPoint
class MainActivity : ComponentActivity() {
    private val viewModel: MainViewModel by viewModels()
    private val routinesViewModel: RoutinesViewModel by viewModels()
    private var pendingApprovalId: String? = null
    private var pendingSettingsStepUp = false

    @Inject
    lateinit var preferences: AppPreferencesRepository

    private val unlockLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            val approvalId = pendingApprovalId
            val settingsStepUp = pendingSettingsStepUp
            pendingApprovalId = null
            pendingSettingsStepUp = false
            if (settingsStepUp) {
                viewModel.dispatch(MainIntent.SettingsStepUpAuthenticationSucceeded)
            } else if (approvalId == null) {
                viewModel.dispatch(MainIntent.LocalAuthenticationSucceeded)
            } else {
                viewModel.dispatch(MainIntent.StepUpAuthenticationSucceeded(approvalId))
            }
        } else {
            pendingApprovalId = null
            pendingSettingsStepUp = false
        }
    }

    private val attachmentLauncher = registerForActivityResult(
        ActivityResultContracts.OpenDocument(),
    ) { uri ->
        uri?.let { viewModel.dispatch(MainIntent.AttachmentSelected(it)) }
    }

    private val audioPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.RequestPermission(),
    ) { granted ->
        if (granted) {
            viewModel.dispatch(MainIntent.ToggleVoiceNote)
        } else {
            viewModel.dispatch(MainIntent.VoicePermissionDenied)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        // Protect the task preview before any preference read completes. The user can opt out
        // from this setting only after the local credential gate has been passed.
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        handleSyncWakeIntent(intent)
        handleInboundIntent(intent)
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                preferences.preferences.collect { stored ->
                    if (stored.blockScreenshots) {
                        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    } else {
                        window.clearFlags(WindowManager.LayoutParams.FLAG_SECURE)
                    }
                }
            }
        }

        setContent {
            HermesTheme {
                val state by viewModel.uiState.collectAsStateWithLifecycle()
                val routinesState by routinesViewModel.uiState.collectAsStateWithLifecycle()
                LaunchedEffect(state.selectedBot, state.section, state.transport) {
                    val selectedBot = state.selectedBot
                    if (state.section == HomeSection.ROUTINES &&
                        selectedBot != null &&
                        state.transport != TransportState.AUTH_EXPIRED
                    ) {
                        routinesViewModel.load(selectedBot)
                    } else if (selectedBot == null ||
                        state.transport == TransportState.AUTH_EXPIRED
                    ) {
                        // Do not leave profile-scoped labels or controls visible after the main
                        // session is revoked or the approved profile is removed.
                        routinesViewModel.clear()
                    }
                }
                HermesHome(
                    state = state,
                    routinesState = routinesState,
                    onIntent = viewModel::dispatch,
                    onRefreshRoutines = routinesViewModel::refresh,
                    onPauseRoutine = routinesViewModel::pause,
                    onResumeRoutine = routinesViewModel::resume,
                    onRequestUnlock = ::requestLocalUnlock,
                    onPickAttachment = { attachmentLauncher.launch(arrayOf("*/*")) },
                    onToggleVoiceNote = ::requestVoiceAction,
                    onRequestApprovalStepUp = ::requestApprovalStepUp,
                    onRequestSettingsStepUp = ::requestSettingsStepUp,
                )
            }
        }
    }

    /**
     * Handle only text shares and explicit HTTP(S) VIEW intents as drafts. No inbound URI is
     * launched, resolved, previewed, or staged; attachments stay on the explicit picker path.
     */
    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleSyncWakeIntent(intent)
        handleInboundIntent(intent)
    }

    /**
     * FCM system-rendered notifications can bypass FirebaseMessagingService while the app is in
     * the background.  The relay's fixed marker is copied into the launch intent, so opening such
     * a notification always schedules a global authenticated cursor wake and a foreground refresh.
     */
    private fun handleSyncWakeIntent(intent: Intent?) {
        val marker = runCatching {
            intent?.getStringExtra(SyncWorkScheduler.KEY_WAKE)
        }.getOrNull()
        if (marker != SyncWorkScheduler.WAKE_VALUE) return
        SyncWorkScheduler.enqueue(applicationContext)
        viewModel.dispatch(MainIntent.Refresh)
    }

    private fun handleInboundIntent(intent: Intent?) {
        if (intent == null) return
        val decision = try {
            InboundIntentPolicy.resolve(
                InboundIntentPayload(
                    action = intent.action,
                    mimeType = intent.type,
                    // Extras come from another application. A malformed parcel must not take
                    // down the main activity or bypass the pure policy boundary.
                    text = runCatching {
                        intent.getCharSequenceExtra(Intent.EXTRA_TEXT)?.toString()
                    }.getOrNull(),
                    dataUri = intent.dataString,
                    hasStream = intent.hasExtra(Intent.EXTRA_STREAM),
                ),
            )
        } catch (_: RuntimeException) {
            InboundIntentDecision.Rejected(RejectionReason.MALFORMED_PAYLOAD)
        }

        when (decision) {
            is InboundIntentDecision.Draft -> viewModel.dispatch(MainIntent.SetDraft(decision.text))
            is InboundIntentDecision.Rejected -> {
                val message = when (decision.reason) {
                    RejectionReason.ATTACHMENT_NOT_SUPPORTED ->
                        "Hermes accepts shared text only; choose files explicitly in Attach."
                    RejectionReason.UNSUPPORTED_MIME_TYPE ->
                        "Hermes accepts plain-text shares only."
                    RejectionReason.EMPTY_TEXT -> "The shared text was empty."
                    RejectionReason.TOO_LARGE -> "The shared text is too large for a draft."
                    RejectionReason.CONTROL_CHARACTER -> "The shared text contains unsupported control characters."
                    RejectionReason.UNSAFE_LINK ->
                        "Hermes accepts only safe HTTP(S) links and does not open them automatically."
                    RejectionReason.MALFORMED_PAYLOAD ->
                        "Hermes could not read that incoming share."
                }
                Toast.makeText(this, message, Toast.LENGTH_SHORT).show()
            }
            InboundIntentDecision.Ignored -> Unit
        }
    }

    override fun onStop() {
        viewModel.onChatScreenHidden()
        super.onStop()
    }

    private fun requestLocalUnlock() {
        val keyguard = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if (!keyguard.isKeyguardSecure) {
            Toast.makeText(
                this,
                "Set a device PIN, password, or biometric before opening Hermes.",
                Toast.LENGTH_LONG,
            ).show()
            return
        }
        val credentialIntent = keyguard.createConfirmDeviceCredentialIntent(
            "Unlock Hermes",
            "Use your device credential to reveal Hermes content.",
        )
        if (credentialIntent == null) {
            Toast.makeText(this, "Device authentication is unavailable.", Toast.LENGTH_LONG).show()
        } else {
            unlockLauncher.launch(credentialIntent)
        }
    }

    private fun requestVoiceAction() {
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.RECORD_AUDIO) ==
            android.content.pm.PackageManager.PERMISSION_GRANTED
        ) {
            viewModel.dispatch(MainIntent.ToggleVoiceNote)
        } else {
            audioPermissionLauncher.launch(Manifest.permission.RECORD_AUDIO)
        }
    }

    private fun requestApprovalStepUp(approvalId: String) {
        authenticateStepUp(
            title = "Approve Hermes action",
            subtitle = "Authenticate to approve this action once.",
            onSuccess = { viewModel.dispatch(MainIntent.StepUpAuthenticationSucceeded(approvalId)) },
            onUnsupported = { requestApprovalCredentialStepUp(approvalId) },
        )
    }

    private fun requestApprovalCredentialStepUp(approvalId: String) {
        val keyguard = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if (!keyguard.isKeyguardSecure) {
            Toast.makeText(this, "Set a device credential before approving Hermes actions.", Toast.LENGTH_LONG).show()
            return
        }
        val credentialIntent = keyguard.createConfirmDeviceCredentialIntent(
            "Approve Hermes action",
            "Authenticate to approve this action once.",
        )
        if (credentialIntent == null) {
            Toast.makeText(this, "Device authentication is unavailable.", Toast.LENGTH_LONG).show()
        } else {
            pendingApprovalId = approvalId
            unlockLauncher.launch(credentialIntent)
        }
    }

    private fun requestSettingsStepUp() {
        authenticateStepUp(
            title = "Change Hermes settings",
            subtitle = "Authenticate to save this sensitive setting.",
            onSuccess = { viewModel.dispatch(MainIntent.SettingsStepUpAuthenticationSucceeded) },
            onUnsupported = { requestSettingsCredentialStepUp() },
        )
    }

    private fun requestSettingsCredentialStepUp() {
        val keyguard = getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        if (!keyguard.isKeyguardSecure) {
            Toast.makeText(this, "Set a device credential before changing sensitive Hermes settings.", Toast.LENGTH_LONG).show()
            return
        }
        val credentialIntent = keyguard.createConfirmDeviceCredentialIntent(
            "Change Hermes settings",
            "Authenticate to save this sensitive setting.",
        )
        if (credentialIntent == null) {
            Toast.makeText(this, "Device authentication is unavailable.", Toast.LENGTH_LONG).show()
        } else {
            pendingSettingsStepUp = true
            unlockLauncher.launch(credentialIntent)
        }
    }

    /**
     * Strong biometric is preferred. DEVICE_CREDENTIAL is included in the same system prompt, so
     * a user can fall back to PIN/password without the app handling credential material. Older or
     * unsupported devices use the existing Keyguard confirmation path instead.
     */
    private fun authenticateStepUp(
        title: String,
        subtitle: String,
        onSuccess: () -> Unit,
        onUnsupported: () -> Unit,
    ) {
        val authenticators = BiometricManager.Authenticators.BIOMETRIC_STRONG or
            BiometricManager.Authenticators.DEVICE_CREDENTIAL
        if (BiometricManager.from(this).canAuthenticate(authenticators) !=
            BiometricManager.BIOMETRIC_SUCCESS
        ) {
            onUnsupported()
            return
        }
        val executor = ContextCompat.getMainExecutor(this)
        val prompt = BiometricPrompt(
            this,
            executor,
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    onSuccess()
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    if (errorCode == BiometricPrompt.ERROR_HW_NOT_PRESENT ||
                        errorCode == BiometricPrompt.ERROR_NO_BIOMETRICS ||
                        errorCode == BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL
                    ) {
                        onUnsupported()
                    } else {
                        Toast.makeText(this@MainActivity, "Device authentication was not completed.", Toast.LENGTH_SHORT).show()
                    }
                }
            },
        )
        val promptInfo = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setAllowedAuthenticators(authenticators)
            .build()
        prompt.authenticate(promptInfo)
    }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun HermesHome(
    state: MainUiState,
    routinesState: RoutinesUiState,
    onIntent: (MainIntent) -> Unit,
    onRefreshRoutines: () -> Unit,
    onPauseRoutine: (String) -> Unit,
    onResumeRoutine: (String) -> Unit,
    onRequestUnlock: () -> Unit,
    onPickAttachment: () -> Unit,
    onToggleVoiceNote: () -> Unit,
    onRequestApprovalStepUp: (String) -> Unit,
    onRequestSettingsStepUp: () -> Unit,
) {
    Surface(modifier = Modifier.fillMaxSize()) {
        if (state.isLocked) {
            LockScreen(onRequestUnlock)
        } else {
            Scaffold(
                topBar = {
                    TopAppBar(
                        title = {
                            Column {
                                Text("Hermes Mobile", fontWeight = FontWeight.SemiBold)
                                Text(
                                    text = "${state.transport.displayLabel()} · ${state.attention.displayLabel()}",
                                    style = MaterialTheme.typography.labelMedium,
                                )
                            }
                        },
                        actions = {
                            IconButton(
                                onClick = { onIntent(MainIntent.Refresh) },
                                modifier = Modifier
                                    .size(48.dp)
                                    .semantics { contentDescription = "Refresh Hermes sync" },
                            ) {
                                Icon(Icons.Outlined.Refresh, contentDescription = null)
                            }
                        },
                    )
                },
                bottomBar = {
                    HermesNavigationBar(state.section, onIntent)
                },
            ) { paddingValues ->
                when (state.section) {
                    HomeSection.CHAT -> ChatSection(
                        state,
                        onIntent,
                        onPickAttachment,
                        onToggleVoiceNote,
                        onRequestApprovalStepUp,
                        paddingValues,
                    )
                    HomeSection.GROUPS -> GroupsSection(state, onIntent, paddingValues)
                    HomeSection.ROUTINES -> RoutinesScreen(
                        state = routinesState,
                        onRefresh = onRefreshRoutines,
                        onPause = onPauseRoutine,
                        onResume = onResumeRoutine,
                        modifier = Modifier.padding(paddingValues),
                    )
                    HomeSection.SETTINGS -> SettingsSection(
                        state,
                        onIntent,
                        onRequestApprovalStepUp,
                        onRequestSettingsStepUp,
                        paddingValues,
                    )
                }
            }
            state.editAsNewConfirmation?.let {
                AlertDialog(
                    onDismissRequest = { onIntent(MainIntent.DismissEditAsNewMessage) },
                    title = { Text("Edit as new message?") },
                    text = {
                        Text(
                            "The original send was rejected or could not be confirmed. " +
                                "Hermes will not retry it automatically. The message will be copied " +
                                "into the composer, and no new send starts until you press Send message.",
                        )
                    },
                    confirmButton = {
                        TextButton(onClick = { onIntent(MainIntent.ConfirmEditAsNewMessage) }) {
                            Text("Edit as new message")
                        }
                    },
                    dismissButton = {
                        TextButton(onClick = { onIntent(MainIntent.DismissEditAsNewMessage) }) {
                            Text("Cancel")
                        }
                    },
                )
            }
        }
    }
}

@Composable
private fun HermesNavigationBar(section: HomeSection, onIntent: (MainIntent) -> Unit) {
    NavigationBar {
        NavigationBarItem(
            selected = section == HomeSection.CHAT,
            onClick = { onIntent(MainIntent.SelectSection(HomeSection.CHAT)) },
            icon = { Icon(Icons.Outlined.ChatBubbleOutline, contentDescription = null) },
            label = { Text("Chat") },
        )
        NavigationBarItem(
            selected = section == HomeSection.GROUPS,
            onClick = { onIntent(MainIntent.SelectSection(HomeSection.GROUPS)) },
            icon = { Icon(Icons.Outlined.Group, contentDescription = null) },
            label = { Text("Groups") },
        )
        NavigationBarItem(
            selected = section == HomeSection.ROUTINES,
            onClick = { onIntent(MainIntent.SelectSection(HomeSection.ROUTINES)) },
            icon = { Icon(Icons.Outlined.Refresh, contentDescription = null) },
            label = { Text("Routines") },
        )
        NavigationBarItem(
            selected = section == HomeSection.SETTINGS,
            onClick = { onIntent(MainIntent.SelectSection(HomeSection.SETTINGS)) },
            icon = { Icon(Icons.Outlined.Settings, contentDescription = null) },
            label = { Text("Settings") },
        )
    }
}

@Composable
private fun ChatSection(
    state: MainUiState,
    onIntent: (MainIntent) -> Unit,
    onPickAttachment: () -> Unit,
    onToggleVoiceNote: () -> Unit,
    onRequestApprovalStepUp: (String) -> Unit,
    paddingValues: PaddingValues,
) {
    Row(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues)
            .padding(horizontal = 12.dp, vertical = 8.dp),
        horizontalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        BotRoster(
            cards = state.botCards,
            selected = state.selectedBot,
            onSelect = { onIntent(MainIntent.SelectBot(it)) },
            modifier = Modifier
                .width(220.dp)
                .fillMaxHeight(),
        )
            ConversationPane(
                state = state,
                onIntent = onIntent,
                onPickAttachment = onPickAttachment,
                onToggleVoiceNote = onToggleVoiceNote,
                onRequestApprovalStepUp = onRequestApprovalStepUp,
            modifier = Modifier
                .weight(1f)
                .fillMaxHeight(),
        )
    }
}

@Composable
private fun BotRoster(
    cards: List<BotCardState>,
    selected: com.hermes.mobile.contract.BotId?,
    onSelect: (com.hermes.mobile.contract.BotId) -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(modifier = modifier) {
        Column(modifier = Modifier.padding(12.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Icon(Icons.Outlined.SmartToy, contentDescription = null)
                Text(
                    text = "Bots",
                    style = MaterialTheme.typography.titleMedium,
                    modifier = Modifier.padding(start = 8.dp),
                )
            }
            HorizontalDivider(modifier = Modifier.padding(vertical = 8.dp))
            if (cards.isEmpty()) {
                Text(
                    "No approved bots are cached. Complete device enrollment to load this roster.",
                    style = MaterialTheme.typography.bodySmall,
                )
            } else {
                LazyColumn(verticalArrangement = Arrangement.spacedBy(8.dp)) {
                    items(cards, key = { "${it.bot.instanceId}:${it.bot.opaqueProfileId}" }) { card ->
                        BotRosterCard(card, selected == card.bot, onSelect)
                    }
                }
            }
        }
    }
}

@Composable
private fun BotRosterCard(
    card: BotCardState,
    selected: Boolean,
    onSelect: (com.hermes.mobile.contract.BotId) -> Unit,
) {
    Surface(
        onClick = { onSelect(card.bot) },
        tonalElevation = if (selected) 3.dp else 0.dp,
        shape = MaterialTheme.shapes.medium,
        modifier = Modifier
            .fillMaxWidth()
            .heightIn(min = 64.dp),
    ) {
        Column(modifier = Modifier.padding(10.dp)) {
            Text(card.displayName, fontWeight = FontWeight.SemiBold)
            Text(card.originLabel, style = MaterialTheme.typography.labelSmall)
            Text(
                "${card.transport.displayLabel()} · ${card.runState.displayLabel()}",
                style = MaterialTheme.typography.labelSmall,
            )
            if (card.attention != AttentionState.NONE) {
                Text(
                    "Attention: ${card.attention.displayLabel()}",
                    style = MaterialTheme.typography.labelSmall,
                )
            }
        }
    }
}

@Composable
private fun ConversationPane(
    state: MainUiState,
    onIntent: (MainIntent) -> Unit,
    onPickAttachment: () -> Unit,
    onToggleVoiceNote: () -> Unit,
    onRequestApprovalStepUp: (String) -> Unit,
    modifier: Modifier = Modifier,
) {
    Card(modifier = modifier) {
        Column(modifier = Modifier.fillMaxSize()) {
            Column(modifier = Modifier.padding(16.dp)) {
                Text(
                    text = state.botCards.firstOrNull { it.bot == state.selectedBot }?.displayName
                        ?: "Select a bot",
                    style = MaterialTheme.typography.titleLarge,
                )
                Text(
                    text = state.botCards.firstOrNull { it.bot == state.selectedBot }?.originLabel
                        ?: "Every message is scoped to an approved instance and profile.",
                    style = MaterialTheme.typography.bodySmall,
                )
            }
            HorizontalDivider()
            ConversationPicker(
                conversations = state.conversations,
                selectedConversationId = state.selectedConversationId?.value,
                isLoading = state.isLoadingConversations,
                isStale = state.conversationsStale,
                canCreate = state.transport == TransportState.CONNECTED &&
                    !state.isAttachmentUploading &&
                    !state.isRecording &&
                    state.pendingVoiceNoteDurationMillis == null &&
                    state.selectedAttachmentIds.isEmpty() &&
                    state.pendingConversationCreate == null,
                canSelect = !state.isAttachmentUploading &&
                    !state.isRecording &&
                    state.pendingVoiceNoteDurationMillis == null &&
                    state.selectedAttachmentIds.isEmpty(),
                onSelect = { onIntent(MainIntent.SelectConversation(it)) },
                onCreate = { onIntent(MainIntent.CreateConversation) },
                modifier = Modifier.padding(horizontal = 12.dp, vertical = 8.dp),
            )
            state.pendingConversationCreate?.let { pending ->
                val retryable = conversationCreateRecoveryAction(pending) ==
                    ConversationCreateRecoveryAction.RETRY_ORIGINAL
                Card(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 4.dp),
                ) {
                    Column(
                        modifier = Modifier.padding(12.dp),
                        verticalArrangement = Arrangement.spacedBy(6.dp),
                    ) {
                        Text(
                            if (retryable) "New chat needs confirmation" else "New chat in progress",
                            fontWeight = FontWeight.SemiBold,
                        )
                        Text(
                            if (retryable) {
                                "The previous New chat request was not confirmed. Retry it with the same request key; Hermes will not create a second conversation."
                            } else {
                                "A New chat request is being completed. Keep this screen open; another conversation cannot be created until it resolves."
                            },
                            style = MaterialTheme.typography.bodySmall,
                        )
                        Button(
                            onClick = { onIntent(MainIntent.RetryCreateConversation) },
                            enabled = retryable && state.transport == TransportState.CONNECTED &&
                                !state.isLoadingConversations &&
                                !state.isAttachmentUploading &&
                                !state.isRecording &&
                                state.pendingVoiceNoteDurationMillis == null,
                            modifier = Modifier.heightIn(min = 48.dp),
                        ) {
                            Text(if (retryable) "Retry new chat" else "Waiting for New chat")
                        }
                    }
                }
            }
            val directRuns = state.directRuns.ifEmpty {
                listOf(state.directRun).filter { run ->
                    run.runId != null && run.state !in setOf(
                        RunState.COMPLETED,
                        RunState.FAILED,
                        RunState.CANCELLED,
                    )
                }
            }
            directRuns.forEach { run ->
                DirectRunControls(
                    state = run,
                    onStop = { onIntent(MainIntent.CancelRun(it)) },
                    onRefresh = { onIntent(MainIntent.RefreshRun(it)) },
                )
            }
            if (state.transcript.isEmpty()) {
                Box(modifier = Modifier.weight(1f).fillMaxWidth(), contentAlignment = Alignment.Center) {
                    Column(
                        modifier = Modifier.padding(24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally,
                        verticalArrangement = Arrangement.spacedBy(8.dp),
                    ) {
                        Text("No messages yet", style = MaterialTheme.typography.titleMedium)
                        Text(
                            "Choose an approved bot, then compose a message. Live content appears only after authenticated sync.",
                            style = MaterialTheme.typography.bodyMedium,
                        )
                    }
                }
            } else {
                LazyColumn(
                    modifier = Modifier.weight(1f),
                    contentPadding = PaddingValues(12.dp),
                    verticalArrangement = Arrangement.spacedBy(10.dp),
                ) {
                    items(state.transcript, key = { it.messageId }) { card ->
                        TranscriptCardView(
                            card = card,
                            onRequestApprovalStepUp = onRequestApprovalStepUp,
                            onRetry = { onIntent(MainIntent.RetrySend(it)) },
                            onEditAsNew = { onIntent(MainIntent.EditAsNewMessage(it)) },
                        )
                    }
                }
            }
            state.pendingVoiceNoteDurationMillis?.let { durationMillis ->
                VoiceNoteReview(durationMillis, onIntent)
            }
            Composer(state, onIntent, onPickAttachment, onToggleVoiceNote)
        }
    }
}

@Composable
private fun VoiceNoteReview(durationMillis: Long, onIntent: (MainIntent) -> Unit) {
    Card(modifier = Modifier.fillMaxWidth().padding(horizontal = 12.dp, vertical = 4.dp)) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Voice note preview", fontWeight = FontWeight.SemiBold)
            Text(
                "AAC-LC/M4A · ${durationMillis / 1_000}s · app-private until you choose upload",
                style = MaterialTheme.typography.bodySmall,
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(onClick = { onIntent(MainIntent.SendVoiceNote) }, modifier = Modifier.heightIn(min = 48.dp)) {
                    Text("Upload voice note")
                }
                Button(onClick = { onIntent(MainIntent.DiscardVoiceNote) }, modifier = Modifier.heightIn(min = 48.dp)) {
                    Text("Discard")
                }
            }
        }
    }
}

@Composable
private fun TranscriptCardView(
    card: TranscriptCard,
    onRequestApprovalStepUp: (String) -> Unit,
    onRetry: (String) -> Unit,
    onEditAsNew: (String) -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Text(card.authorLabel, fontWeight = FontWeight.SemiBold)
                Text(
                    when {
                        card.delivery == DeliveryState.PENDING -> "Pending"
                        card.delivery == DeliveryState.FAILED -> when (card.operationState) {
                            com.hermes.mobile.data.MobileOperationStates.REJECTED -> "Rejected"
                            com.hermes.mobile.data.MobileOperationStates.CONFLICT -> "Blocked"
                            com.hermes.mobile.data.MobileOperationStates.INDETERMINATE -> "Needs review"
                            com.hermes.mobile.data.MobileOperationStates.UNCERTAIN -> "Outcome uncertain"
                            else -> "Failed"
                        }
                        card.runState != null -> card.runState.displayLabel()
                        else -> "Sent"
                    },
                    style = MaterialTheme.typography.labelSmall,
                )
            }
            card.parts.forEach { MessagePartView(it, onRequestApprovalStepUp) }
            if (card.delivery == DeliveryState.FAILED && card.operationId != null) {
                when (sendRecoveryAction(card.operationState)) {
                    SendRecoveryAction.RETRY_ORIGINAL -> TextButton(
                        onClick = { onRetry(card.operationId) },
                        modifier = Modifier.heightIn(min = 48.dp),
                    ) {
                        Text("Retry original send")
                    }
                    SendRecoveryAction.EDIT_AS_NEW -> {
                        Text(
                            "The original operation is retained and will not be retried automatically.",
                            style = MaterialTheme.typography.bodySmall,
                        )
                        TextButton(
                            onClick = { onEditAsNew(card.operationId) },
                            modifier = Modifier.heightIn(min = 48.dp),
                        ) {
                            Text("Edit as new message")
                        }
                    }
                    SendRecoveryAction.NONE -> Unit
                }
            }
        }
    }
}

@Composable
private fun MessagePartView(
    part: MessagePart,
    onRequestApprovalStepUp: (String) -> Unit,
) {
    when (part) {
        is MessagePart.Text -> Text(part.text, style = MaterialTheme.typography.bodyLarge)
        is MessagePart.Link -> {
            val safeUrl = LinkPolicy.normalizeExternalUrl(part.url)
            val context = LocalContext.current
            Text(
                if (safeUrl == null) "Blocked link" else "Link: ${part.title ?: safeUrl}",
                style = MaterialTheme.typography.bodyMedium,
            )
            if (safeUrl != null) {
                TextButton(
                    onClick = {
                        runCatching {
                            CustomTabsIntent.Builder()
                                .build()
                                .launchUrl(context, Uri.parse(safeUrl))
                        }.onFailure {
                            Toast.makeText(context, "No browser is available for this link.", Toast.LENGTH_SHORT).show()
                        }
                    },
                    modifier = Modifier.heightIn(min = 48.dp),
                ) {
                    Text("Open safely")
                }
            }
        }
        is MessagePart.Image -> Text("Image attachment", style = MaterialTheme.typography.bodyMedium)
        is MessagePart.File -> Text(
            "File attachment${part.displayName?.let { ": $it" } ?: ""}",
            style = MaterialTheme.typography.bodyMedium,
        )
        is MessagePart.Audio -> Text(
            "Voice note · ${part.durationMs / 1_000}s${if (part.transcript.isNullOrBlank()) "" else " · transcript available"}",
            style = MaterialTheme.typography.bodyMedium,
        )
        is MessagePart.ToolEvent -> Text(
            "Tool · ${part.label} · ${part.state}",
            style = MaterialTheme.typography.bodyMedium,
        )
        is MessagePart.Approval -> AssistChip(
            onClick = { onRequestApprovalStepUp(part.requestId) },
            modifier = Modifier.heightIn(min = 48.dp),
            label = { Text("Approval required: ${part.title}") },
        )
        is MessagePart.Artifact -> Text(
            "Artifact · ${part.displayName} (${part.mimeType})",
            style = MaterialTheme.typography.bodyMedium,
        )
    }
}

@Composable
private fun Composer(
    state: MainUiState,
    onIntent: (MainIntent) -> Unit,
    onPickAttachment: () -> Unit,
    onToggleVoiceNote: () -> Unit,
) {
    val composerBusy = state.isLoadingConversations || state.isAttachmentUploading
    Column(modifier = Modifier.padding(12.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            verticalAlignment = Alignment.Bottom,
            horizontalArrangement = Arrangement.spacedBy(6.dp),
        ) {
            IconButton(
                onClick = onPickAttachment,
                enabled = !composerBusy,
                modifier = Modifier.size(48.dp).semantics { contentDescription = "Add attachment" },
            ) {
                Icon(Icons.Outlined.AttachFile, contentDescription = null)
            }
            OutlinedTextField(
                value = state.draft,
                onValueChange = { onIntent(MainIntent.SetDraft(it)) },
                modifier = Modifier.weight(1f),
                enabled = !composerBusy,
                minLines = 1,
                maxLines = 4,
                label = { Text("Message") },
                supportingText = {
                    Text(
                        if (state.selectedAttachmentCount == 0) {
                            "Links stay structured; attachments remain private until sent."
                        } else {
                            "${state.selectedAttachmentCount} attachment(s) ready for this message."
                        },
                    )
                },
            )
            if (state.selectedAttachmentCount > 0) {
                IconButton(
                    onClick = { onIntent(MainIntent.ClearAttachments) },
                    enabled = !composerBusy,
                    modifier = Modifier
                        .size(48.dp)
                        .semantics { contentDescription = "Clear attachments" },
                ) {
                    Icon(Icons.Outlined.Close, contentDescription = null)
                }
            }
            IconButton(
                onClick = onToggleVoiceNote,
                enabled = !state.isAttachmentUploading &&
                    (!state.isLoadingConversations || state.isRecording),
                modifier = Modifier.size(48.dp).semantics { contentDescription = "Record voice note" },
            ) {
                Icon(
                    if (state.isRecording) Icons.Outlined.Stop else Icons.Outlined.Mic,
                    contentDescription = null,
                )
            }
            IconButton(
                onClick = { onIntent(MainIntent.SendDraft) },
                enabled = !composerBusy,
                modifier = Modifier.size(48.dp).semantics { contentDescription = "Send message" },
            ) {
                Icon(Icons.Outlined.Send, contentDescription = null)
            }
        }
        state.composerMessage?.let {
            Text(it, style = MaterialTheme.typography.labelMedium)
        }
    }
}

@Composable
private fun GroupsSection(
    state: MainUiState,
    onIntent: (MainIntent) -> Unit,
    paddingValues: PaddingValues,
) {
    val group = state.group
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues)
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Groups", style = MaterialTheme.typography.headlineSmall)
        Text(
            "Group turns are coordinated by Hermes. The phone only submits durable events and observes the run.",
            style = MaterialTheme.typography.bodyMedium,
        )
        if (group.groupId == null) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp),
                ) {
                    Text("No group is active.", fontWeight = FontWeight.SemiBold)
                    Text(
                        "Choose two to six approved bots from this Hermes installation to create a group.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    if (state.botCards.isEmpty()) {
                        Text("Connect an approved device profile before creating a group.")
                    } else {
                        state.botCards.forEach { card ->
                            Row(
                                modifier = Modifier.fillMaxWidth(),
                                verticalAlignment = Alignment.CenterVertically,
                            ) {
                                Checkbox(
                                    checked = card.bot in group.selectedBotIds,
                                    onCheckedChange = {
                                        onIntent(MainIntent.ToggleGroupBot(card.bot))
                                    },
                                )
                                Column {
                                    Text(card.displayName, fontWeight = FontWeight.SemiBold)
                                    Text(
                                        card.originLabel,
                                        style = MaterialTheme.typography.labelSmall,
                                    )
                                }
                            }
                        }
                        Button(
                            onClick = { onIntent(MainIntent.CreateGroup) },
                            enabled = group.selectedBotIds.size in 2..6 && !group.isMutating,
                            modifier = Modifier.fillMaxWidth(),
                        ) {
                            Text(if (group.isMutating) "Creating…" else "Create group")
                        }
                    }
                }
            }
        } else {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text(
                        if (group.lifecycle == GroupLifecycle.ACTIVE) "Active group" else "Stopped group",
                        fontWeight = FontWeight.SemiBold,
                    )
                    Text(
                        "${group.members.size} bots · authority epoch ${group.authorityEpoch ?: "—"}",
                        style = MaterialTheme.typography.labelSmall,
                    )
                }
                IconButton(
                    onClick = { onIntent(MainIntent.RefreshGroup) },
                    enabled = !group.isLoading && !group.isMutating,
                    modifier = Modifier
                        .size(48.dp)
                        .semantics { contentDescription = "Refresh group" },
                ) {
                    Icon(Icons.Outlined.Refresh, contentDescription = null)
                }
            }
            group.members.forEach { member ->
                Card(modifier = Modifier.fillMaxWidth()) {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(14.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(member.label, fontWeight = FontWeight.SemiBold)
                            Text(
                                "Origin: Instance ${member.bot.instanceId.takeLast(6)}",
                                style = MaterialTheme.typography.labelSmall,
                            )
                            if (member.memberId == group.coordinatorMemberId) {
                                Text("Coordinator", style = MaterialTheme.typography.labelSmall)
                            }
                        }
                        if (group.lifecycle == GroupLifecycle.ACTIVE) {
                            IconButton(
                                onClick = { onIntent(MainIntent.RemoveGroupMember(member.memberId)) },
                                enabled = group.members.size > 2 && !group.isMutating,
                                modifier = Modifier
                                    .size(48.dp)
                                    .semantics { contentDescription = "Remove ${member.label} from group" },
                            ) {
                                Icon(Icons.Outlined.Close, contentDescription = null)
                            }
                        }
                    }
                }
            }
            if (group.lifecycle == GroupLifecycle.ACTIVE) {
                val memberBots = group.members.map { it.bot }.toSet()
                val availableBots = state.botCards.filter { it.bot !in memberBots }
                if (availableBots.isNotEmpty()) {
                    Text("Add an approved bot", fontWeight = FontWeight.SemiBold)
                    availableBots.forEach { card ->
                        AssistChip(
                            onClick = { onIntent(MainIntent.AddGroupMember(card.bot)) },
                            enabled = group.members.size < 6 && !group.isMutating,
                            label = { Text("Add ${card.displayName}") },
                        )
                    }
                }
                OutlinedTextField(
                    value = group.draft,
                    onValueChange = { onIntent(MainIntent.SetGroupDraft(it)) },
                    modifier = Modifier.fillMaxWidth(),
                    minLines = 2,
                    maxLines = 6,
                    label = { Text("Group message") },
                    supportingText = { Text("Up to 200,000 characters; turns are durable and run on Hermes.") },
                    enabled = !group.isMutating,
                )
                Button(
                    onClick = { onIntent(MainIntent.SendGroupMessage) },
                    enabled = group.draft.isNotBlank() && !group.isMutating,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Outlined.Send, contentDescription = null)
                    Text(" Send group message")
                }
                Button(
                    onClick = { onIntent(MainIntent.StopGroup) },
                    enabled = !group.isMutating,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Icon(Icons.Outlined.Stop, contentDescription = null)
                    Text(" Stop group")
                }
            } else {
                Text(
                    "This group is stopped. Its membership and turns are read-only.",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Button(
                    onClick = { onIntent(MainIntent.ClearGroup) },
                    enabled = !group.isMutating,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    Text("Create another group")
                }
            }
            group.lastRun?.let { run ->
                Text("Last turn: ${run.state} · run ${run.runId.takeLast(6)}", style = MaterialTheme.typography.labelSmall)
            }
        }
        group.message?.let { message ->
            Text(message, style = MaterialTheme.typography.labelMedium)
        }
    }
}

@Composable
private fun SettingsSection(
    state: MainUiState,
    onIntent: (MainIntent) -> Unit,
    onRequestApprovalStepUp: (String) -> Unit,
    onRequestSettingsStepUp: () -> Unit,
    paddingValues: PaddingValues,
) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(paddingValues)
            .padding(16.dp)
            .verticalScroll(rememberScrollState()),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Text("Settings", style = MaterialTheme.typography.headlineSmall)
        EnrollmentCard(state, onIntent)
        HostSettingsCard(state.settings, state.selectedBot != null, onIntent, onRequestSettingsStepUp)
        Card(modifier = Modifier.fillMaxWidth()) {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Text("Screenshot protection", fontWeight = FontWeight.SemiBold)
                    Text(
                        "Keep Hermes content out of screenshots and recent-app previews.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Switch(
                    checked = state.blockScreenshots,
                    onCheckedChange = { onIntent(MainIntent.SetScreenshotProtection(it)) },
                    modifier = Modifier.semantics { contentDescription = "Screenshot protection" },
                )
            }
        }
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                Text("Local app lock", fontWeight = FontWeight.SemiBold)
                Text("The app locks after five minutes and uses the device credential to unlock.")
                Text("Sensitive settings and approvals require a separate step-up signature.")
            }
        }
        if (state.pendingApprovals.isNotEmpty()) {
            Card(modifier = Modifier.fillMaxWidth()) {
                Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    Text("Pending approvals", fontWeight = FontWeight.SemiBold)
                    state.pendingApprovals.forEach { approval ->
                        Text(approval.summary, style = MaterialTheme.typography.bodyMedium)
                        Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                            Button(
                                onClick = { onRequestApprovalStepUp(approval.approvalId) },
                                modifier = Modifier.heightIn(min = 48.dp),
                            ) {
                                Text("Approve once")
                            }
                            Button(
                                onClick = { onIntent(MainIntent.DenyApproval(approval.approvalId)) },
                                modifier = Modifier.heightIn(min = 48.dp),
                            ) {
                                Text("Deny")
                            }
                        }
                    }
                    Text("Approve once or deny after Hermes re-fetches the pending request.")
                }
            }
        }
    }
}

@Composable
private fun HostSettingsCard(
    settings: SettingsUiState,
    hasSelectedBot: Boolean,
    onIntent: (MainIntent) -> Unit,
    onRequestSettingsStepUp: () -> Unit,
) {
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Host settings", fontWeight = FontWeight.SemiBold)
            when {
                !hasSelectedBot -> Text("Select an approved bot to load its host settings.")
                settings.isLoading -> Text("Loading settings from the approved Hermes host…")
                settings.profileId == null -> Text(settings.message ?: "Host settings are not loaded yet.")
                else -> {
                    Text("Revision ${settings.revision ?: "unknown"}; safe edits use the host ETag.", style = MaterialTheme.typography.bodySmall)
                    OutlinedTextField(
                        value = settings.draftDisplayName,
                        onValueChange = { onIntent(MainIntent.SetSettingsDisplayName(it)) },
                        label = { Text("Display name") },
                        singleLine = true,
                        enabled = !settings.isSaving,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = settings.draftTitle,
                        onValueChange = { onIntent(MainIntent.SetSettingsTitle(it)) },
                        label = { Text("Title") },
                        singleLine = true,
                        enabled = !settings.isSaving,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    OutlinedTextField(
                        value = settings.draftAvatar,
                        onValueChange = { onIntent(MainIntent.SetSettingsAvatar(it)) },
                        label = { Text("Avatar reference") },
                        singleLine = true,
                        enabled = !settings.isSaving,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    settings.notificationsEnabled?.let { enabled ->
                        Row(
                            modifier = Modifier.fillMaxWidth(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text("Notifications", fontWeight = FontWeight.SemiBold)
                                Text("Use the host-defined notification preferences.", style = MaterialTheme.typography.bodySmall)
                            }
                            Switch(
                                checked = settings.draftNotificationsEnabled ?: enabled,
                                onCheckedChange = { onIntent(MainIntent.SetSettingsNotifications(it)) },
                            )
                        }
                    }
                    Text(
                        "Privacy preferences and approval policy remain host-controlled; Hermes does not expose an untyped policy editor.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    Button(
                        onClick = { onIntent(MainIntent.SaveSettings) },
                        enabled = !settings.isSaving,
                        modifier = Modifier.heightIn(min = 48.dp),
                    ) {
                        Text("Save safe settings")
                    }
                    HorizontalDivider()
                    Text("Sensitive persona", fontWeight = FontWeight.SemiBold)
                    Text(
                        "Changing the persona requires a fresh host challenge and device authentication.",
                        style = MaterialTheme.typography.bodySmall,
                    )
                    OutlinedTextField(
                        value = settings.draftPersona,
                        onValueChange = { onIntent(MainIntent.SetSettingsPersona(it)) },
                        label = { Text("Persona") },
                        minLines = 3,
                        maxLines = 8,
                        enabled = !settings.isSaving,
                        modifier = Modifier.fillMaxWidth(),
                    )
                    Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                        Button(
                            onClick = { onIntent(MainIntent.PrepareSensitiveSettings) },
                            enabled = !settings.isSaving,
                            modifier = Modifier.heightIn(min = 48.dp),
                        ) {
                            Text("Prepare step-up")
                        }
                        if (settings.stepUpReady) {
                            Button(
                                onClick = onRequestSettingsStepUp,
                                enabled = !settings.isSaving,
                                modifier = Modifier.heightIn(min = 48.dp),
                            ) {
                                Text("Authenticate & save")
                            }
                        }
                    }
                    settings.message?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
                }
            }
        }
    }
}

@Composable
private fun EnrollmentCard(state: MainUiState, onIntent: (MainIntent) -> Unit) {
    val enrollment = state.enrollment
    val busy = enrollment.phase == EnrollmentPhase.AUTHORIZING ||
        enrollment.phase == EnrollmentPhase.CONNECTING
    Card(modifier = Modifier.fillMaxWidth()) {
        Column(modifier = Modifier.padding(16.dp), verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Device enrollment", fontWeight = FontWeight.SemiBold)
            Text(
                "Sign in through Cloudflare Access, give the one-time code to the Hermes host operator, then check approval. The code and OAuth result stay in memory only.",
                style = MaterialTheme.typography.bodySmall,
            )
            OutlinedTextField(
                value = enrollment.deviceLabel,
                onValueChange = { onIntent(MainIntent.SetDeviceLabel(it)) },
                label = { Text("Device label") },
                singleLine = true,
                enabled = !busy,
                modifier = Modifier.fillMaxWidth(),
            )
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                Button(
                    onClick = { onIntent(MainIntent.StartEnrollment) },
                    enabled = !busy,
                    modifier = Modifier.heightIn(min = 48.dp),
                ) {
                    Text(if (enrollment.phase == EnrollmentPhase.CONNECTED) "Enroll another device" else "Sign in")
                }
                if (enrollment.phase == EnrollmentPhase.AWAITING_APPROVAL) {
                    Button(
                        onClick = { onIntent(MainIntent.CheckEnrollment) },
                        modifier = Modifier.heightIn(min = 48.dp),
                    ) {
                        Text("Check approval")
                    }
                }
            }
            enrollment.enrollmentCode?.let { code ->
                SelectionContainer {
                    Text("One-time enrollment code: $code", fontWeight = FontWeight.SemiBold)
                }
            }
            Text(
                text = "Status: ${enrollment.phase.displayLabel()}",
                style = MaterialTheme.typography.labelMedium,
            )
            enrollment.message?.let { Text(it, style = MaterialTheme.typography.bodySmall) }
        }
    }
}

@Composable
private fun LockScreen(onRequestUnlock: () -> Unit) {
    Column(
        modifier = Modifier
            .fillMaxSize()
            .padding(32.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.Center,
    ) {
        Icon(Icons.Outlined.Lock, contentDescription = null, modifier = Modifier.size(48.dp))
        Text(
            "Hermes is locked",
            style = MaterialTheme.typography.headlineSmall,
            modifier = Modifier.padding(top = 16.dp),
        )
        Text(
            "Authenticate with the device credential to reveal instance, bot, and message content.",
            style = MaterialTheme.typography.bodyLarge,
            modifier = Modifier.padding(top = 8.dp),
        )
        Button(
            onClick = onRequestUnlock,
            modifier = Modifier
                .padding(top = 20.dp)
                .heightIn(min = 48.dp),
        ) {
            Text("Unlock with device credential")
        }
    }
}

private fun TransportState.displayLabel(): String = when (this) {
    TransportState.CONNECTED -> "Connected"
    TransportState.STALE -> "Syncing"
    TransportState.DISCONNECTED -> "Disconnected"
    TransportState.AUTH_EXPIRED -> "Sign-in expired"
}

private fun AttentionState.displayLabel(): String = when (this) {
    AttentionState.NONE -> "No attention needed"
    AttentionState.UNREAD -> "Unread"
    AttentionState.NEEDS_APPROVAL -> "Approval needed"
    AttentionState.NEEDS_ANSWER -> "Answer needed"
    AttentionState.FAILED -> "Failed"
}

private fun RunState.displayLabel(): String = when (this) {
    RunState.QUEUED -> "Queued"
    RunState.THINKING -> "Thinking"
    RunState.TOOL_RUNNING -> "Tool running"
    RunState.WAITING_FOR_USER -> "Waiting for you"
    RunState.APPROVAL_REQUIRED -> "Approval required"
    RunState.COMPLETED -> "Completed"
    RunState.FAILED -> "Failed"
    RunState.CANCELLED -> "Cancelled"
    RunState.INDETERMINATE -> "Needs review"
}

private fun EnrollmentPhase.displayLabel(): String = when (this) {
    EnrollmentPhase.IDLE -> "Not connected"
    EnrollmentPhase.AUTHORIZING -> "Signing in"
    EnrollmentPhase.AWAITING_APPROVAL -> "Waiting for host approval"
    EnrollmentPhase.CONNECTING -> "Establishing session"
    EnrollmentPhase.CONNECTED -> "Connected"
    EnrollmentPhase.ERROR -> "Needs attention"
}
