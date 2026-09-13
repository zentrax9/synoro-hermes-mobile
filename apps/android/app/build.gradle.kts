import java.io.File
import java.net.URI
import java.security.MessageDigest
import org.gradle.api.artifacts.component.ModuleComponentIdentifier

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.serialization)
    alias(libs.plugins.ksp)
    alias(libs.plugins.hilt)
    alias(libs.plugins.compose.compiler)
    alias(libs.plugins.kotlin.kapt)
}

// Public installation coordinates are build configuration, not Hermes secrets. Keep them in
// explicit Gradle properties so they do not become new HERMES_* environment/config knobs.
fun configuredCoordinate(propertyName: String, fallback: String): String =
    project.providers.gradleProperty(propertyName).orElse(fallback).get()

fun configuredOptional(propertyName: String, environmentName: String): String? =
    project.providers.gradleProperty(propertyName)
        .orElse(project.providers.environmentVariable(environmentName))
        .orElse("")
        .get()
        .takeIf { it.isNotBlank() }

fun isPlaceholder(value: String): Boolean =
    value.isBlank() ||
        value.contains(".invalid", ignoreCase = true) ||
        Regex("(^|[./])example($|[./])", RegexOption.IGNORE_CASE).containsMatchIn(value) ||
        value.contains("configure-at-build-time", ignoreCase = true) ||
        value.contains("placeholder", ignoreCase = true) ||
        value.contains("changeme", ignoreCase = true) ||
        Regex("^<[^>]+>$").matches(value)

fun sha256(file: File): String {
    val digest = MessageDigest.getInstance("SHA-256")
    file.inputStream().use { input ->
        val buffer = ByteArray(DEFAULT_BUFFER_SIZE)
        while (true) {
            val read = input.read(buffer)
            if (read < 0) break
            digest.update(buffer, 0, read)
        }
    }
    return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
}

fun String.jsonEscape(): String = buildString {
    for (character in this@jsonEscape) {
        when (character) {
            '\\' -> append("\\\\")
            '"' -> append("\\\"")
            '\b' -> append("\\b")
            '\u000C' -> append("\\f")
            '\n' -> append("\\n")
            '\r' -> append("\\r")
            '\t' -> append("\\t")
            in '\u0000'..'\u001f' -> append("\\u").append(character.code.toString(16).padStart(4, '0'))
            else -> append(character)
        }
    }
}

fun String.asBuildConfigString(): String =
    "\"${replace("\\", "\\\\").replace("\"", "\\\"").replace("\n", "\\n")}\""

fun requireHttpsCoordinate(name: String, value: String, allowPath: Boolean = true) {
    val uri = runCatching { URI(value) }.getOrNull()
    require(
        uri?.scheme.equals("https", ignoreCase = true) &&
            !uri.host.isNullOrBlank() &&
            uri.userInfo == null &&
            uri.query == null &&
            uri.fragment == null &&
            (allowPath || uri.path.isNullOrEmpty() || uri.path == "/"),
    ) {
        "$name must be an absolute HTTPS URL without credentials, a query, or a fragment."
    }
}

fun requireFirebaseCoordinate(name: String, value: String, pattern: Regex) {
    require(!isPlaceholder(value) && pattern.matches(value)) {
        "$name is not a valid Firebase installation coordinate."
    }
}

val mobileBaseUrl = configuredCoordinate(
    "hermes.mobileBaseUrl",
    "https://invalid.invalid",
)
val cloudflareIssuer = configuredCoordinate(
    "hermes.cloudflareIssuer",
    "https://invalid.invalid",
)
val cloudflareResource = configuredCoordinate(
    "hermes.cloudflareResource",
    "https://invalid.invalid",
)
val oauthClientId = configuredCoordinate(
    "hermes.oauthClientId",
    "configure-at-build-time",
)
val oauthAuthorizationEndpoint = configuredCoordinate(
    "hermes.oauthAuthorizationEndpoint",
    "https://invalid.invalid/authorize",
)
val oauthTokenEndpoint = configuredCoordinate(
    "hermes.oauthTokenEndpoint",
    "https://invalid.invalid/oauth2/token",
)
// Firebase application coordinates are installation-specific but are not credentials. They are
// injected at release build time so the repository never needs a google-services.json file (or
// a generated resource containing an installation's project identifiers).
val firebaseProjectId = configuredCoordinate(
    "hermes.firebaseProjectId",
    "configure-at-build-time",
)
val firebaseApplicationId = configuredCoordinate(
    "hermes.firebaseApplicationId",
    "configure-at-build-time",
)
val firebaseApiKey = configuredCoordinate(
    "hermes.firebaseApiKey",
    "configure-at-build-time",
)
val firebaseSenderId = configuredCoordinate(
    "hermes.firebaseSenderId",
    "configure-at-build-time",
)
val firebaseConfigured = listOf(
    firebaseProjectId,
    firebaseApplicationId,
    firebaseApiKey,
    firebaseSenderId,
).none(::isPlaceholder)

// Release signing material is supplied by the CI/release environment. Never commit a
// keystore or its passwords to this repository. The release gate below fails closed when
// any value is missing, points at a non-file, or still names the Android debug keystore.
val releaseKeystorePath = configuredOptional("hermes.releaseKeystore", "HERMES_RELEASE_KEYSTORE")
val releaseStorePassword = configuredOptional("hermes.releaseStorePassword", "HERMES_RELEASE_STORE_PASSWORD")
val releaseKeyAlias = configuredOptional("hermes.releaseKeyAlias", "HERMES_RELEASE_KEY_ALIAS")
val releaseKeyPassword = configuredOptional("hermes.releaseKeyPassword", "HERMES_RELEASE_KEY_PASSWORD")

android {
    namespace = "com.hermes.mobile"
    compileSdk = 36

    signingConfigs {
        create("release") {
            releaseKeystorePath?.let { storeFile = file(it) }
            releaseStorePassword?.let { storePassword = it }
            releaseKeyAlias?.let { keyAlias = it }
            releaseKeyPassword?.let { keyPassword = it }
        }
    }

    defaultConfig {
        applicationId = "com.hermes.mobile"
        minSdk = 28
        targetSdk = 36
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables.useSupportLibrary = true
        buildConfigField("String", "MOBILE_BASE_URL", mobileBaseUrl.asBuildConfigString())
        // Installation-specific OAuth/tunnel coordinates are supplied by the release build.
        // These placeholders deliberately make enrollment fail closed until configured.
        buildConfigField("String", "CLOUDFLARE_ISSUER", cloudflareIssuer.asBuildConfigString())
        buildConfigField("String", "CLOUDFLARE_RESOURCE", cloudflareResource.asBuildConfigString())
        buildConfigField("String", "OAUTH_CLIENT_ID", oauthClientId.asBuildConfigString())
        buildConfigField(
            "String",
            "OAUTH_AUTHORIZATION_ENDPOINT",
            oauthAuthorizationEndpoint.asBuildConfigString(),
        )
        buildConfigField(
            "String",
            "OAUTH_TOKEN_ENDPOINT",
            oauthTokenEndpoint.asBuildConfigString(),
        )
        buildConfigField("String", "FIREBASE_PROJECT_ID", firebaseProjectId.asBuildConfigString())
        buildConfigField("String", "FIREBASE_APPLICATION_ID", firebaseApplicationId.asBuildConfigString())
        buildConfigField("String", "FIREBASE_API_KEY", firebaseApiKey.asBuildConfigString())
        buildConfigField("String", "FIREBASE_SENDER_ID", firebaseSenderId.asBuildConfigString())
        buildConfigField("Boolean", "FIREBASE_CONFIGURED", firebaseConfigured.toString())
    }

    buildTypes {
        release {
            isDebuggable = false
            signingConfig = signingConfigs.getByName("release")
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    packaging {
        resources.excludes += "/META-INF/{AL2.0,LGPL2.1}"
    }

    lint {
        abortOnError = true
    }
}

tasks.register("verifyReleaseConfiguration") {
    doLast {
        val urlValues = mapOf(
            "hermes.mobileBaseUrl" to mobileBaseUrl,
            "hermes.cloudflareIssuer" to cloudflareIssuer,
            "hermes.cloudflareResource" to cloudflareResource,
            "hermes.oauthAuthorizationEndpoint" to oauthAuthorizationEndpoint,
            "hermes.oauthTokenEndpoint" to oauthTokenEndpoint,
        )
        val scalarValues = mapOf(
            "hermes.oauthClientId" to oauthClientId,
            "hermes.firebaseProjectId" to firebaseProjectId,
            "hermes.firebaseApplicationId" to firebaseApplicationId,
            "hermes.firebaseApiKey" to firebaseApiKey,
            "hermes.firebaseSenderId" to firebaseSenderId,
        )
        require((urlValues.values + scalarValues.values).none(::isPlaceholder)) {
            "Release coordinates are placeholders. Supply the -Phermes.* Gradle properties for this installation."
        }
        urlValues.forEach { (name, value) ->
            requireHttpsCoordinate(name, value, allowPath = name != "hermes.mobileBaseUrl")
        }
        require(oauthClientId.none { it.isWhitespace() || it.isISOControl() }) {
            "hermes.oauthClientId must not contain whitespace or control characters."
        }
        requireFirebaseCoordinate(
            "hermes.firebaseProjectId",
            firebaseProjectId,
            Regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$"),
        )
        requireFirebaseCoordinate(
            "hermes.firebaseApplicationId",
            firebaseApplicationId,
            Regex("^1:[0-9]{6,}:android:[A-Za-z0-9_-]{8,}$"),
        )
        requireFirebaseCoordinate(
            "hermes.firebaseApiKey",
            firebaseApiKey,
            Regex("^AIza[A-Za-z0-9_-]{20,}$"),
        )
        requireFirebaseCoordinate(
            "hermes.firebaseSenderId",
            firebaseSenderId,
            Regex("^[0-9]{6,}$"),
        )
    }
}

tasks.register("verifyReleaseSigning") {
    doLast {
        val values = mapOf(
            "hermes.releaseKeystore/HERMES_RELEASE_KEYSTORE" to releaseKeystorePath,
            "hermes.releaseStorePassword/HERMES_RELEASE_STORE_PASSWORD" to releaseStorePassword,
            "hermes.releaseKeyAlias/HERMES_RELEASE_KEY_ALIAS" to releaseKeyAlias,
            "hermes.releaseKeyPassword/HERMES_RELEASE_KEY_PASSWORD" to releaseKeyPassword,
        )
        require(values.values.all { value -> !value.isNullOrBlank() && !isPlaceholder(value) }) {
            "Release signing is not configured. Supply the external keystore path and passwords through the hermes.release* Gradle properties or HERMES_RELEASE_* environment variables."
        }

        val keystore = project.file(requireNotNull(releaseKeystorePath))
        require(keystore.isFile) {
            "The configured release keystore is missing or is not a regular file."
        }
        require(!keystore.name.equals("debug.keystore", ignoreCase = true)) {
            "The Android debug keystore cannot sign a release artifact."
        }
        require(!android.buildTypes.getByName("release").isDebuggable) {
            "The release build type must remain non-debuggable."
        }
    }
}

val verificationMetadataFile = rootProject.file("gradle/verification-metadata.xml")
val dependencyChecksumReport = layout.buildDirectory.file("reports/dependencies/release-runtime.sha256")
val releaseSbomReport = layout.buildDirectory.file("reports/sbom/release.cdx.json")
val releaseApk = layout.buildDirectory.file("outputs/apk/release/app-release.apk")
val releaseApkChecksum = layout.buildDirectory.file("outputs/apk/release/app-release.apk.sha256")

tasks.register("verifyDependencyVerificationMetadata") {
    inputs.file(verificationMetadataFile)
    doLast {
        require(verificationMetadataFile.isFile) {
            "Missing gradle/verification-metadata.xml. On an Android-enabled release host, run ./gradlew --write-verification-metadata sha256 dependencies and commit the generated metadata."
        }
        val metadata = verificationMetadataFile.readText()
        require("<verification-metadata" in metadata && "</verification-metadata>" in metadata) {
            "gradle/verification-metadata.xml is not a valid Gradle verification metadata document."
        }
        require(Regex("<sha256\\s+value=\"[0-9a-fA-F]{64}\"").containsMatchIn(metadata)) {
            "gradle/verification-metadata.xml contains no SHA-256 artifact verification entries."
        }
    }
}

tasks.register("generateDependencyChecksums") {
    outputs.file(dependencyChecksumReport)
    outputs.upToDateWhen { false }
    doLast {
        val artifacts = configurations.getByName("releaseRuntimeClasspath")
            .incoming
            .artifacts
            .artifacts
            .mapNotNull { artifact ->
                val module = artifact.id.componentIdentifier as? ModuleComponentIdentifier ?: return@mapNotNull null
                val file = artifact.file
                require(file.isFile) { "Resolved dependency artifact is not a regular file: ${file.name}" }
                val coordinate = "${module.group}:${module.module}:${module.version}"
                "${sha256(file)}  $coordinate  ${file.name}"
            }
            .distinct()
            .sorted()

        require(artifacts.isNotEmpty()) {
            "No release runtime dependency artifacts were resolved; refusing to write an empty checksum report."
        }
        dependencyChecksumReport.get().asFile.apply {
            parentFile.mkdirs()
            writeText(artifacts.joinToString("\n", postfix = "\n"))
        }
    }
}

tasks.register("verifyDependencyChecksums") {
    dependsOn("verifyDependencyVerificationMetadata", "generateDependencyChecksums")
    doLast {
        val lines = dependencyChecksumReport.get().asFile.readLines().filter { it.isNotBlank() }
        require(lines.isNotEmpty()) { "The dependency checksum report is empty." }
        require(lines.all { line -> Regex("[0-9a-f]{64}\\s{2}\\S.+").matches(line) }) {
            "The dependency checksum report contains a malformed entry."
        }
    }
}

tasks.register("generateReleaseSbom") {
    outputs.file(releaseSbomReport)
    outputs.upToDateWhen { false }
    doLast {
        val entries = configurations.getByName("releaseRuntimeClasspath")
            .incoming
            .artifacts
            .artifacts
            .mapNotNull { artifact ->
                val module = artifact.id.componentIdentifier as? ModuleComponentIdentifier ?: return@mapNotNull null
                val file = artifact.file
                val purl = "pkg:maven/${module.group}/${module.module}@${module.version}"
                val component = buildString {
                    append("{\"type\":\"library\",\"group\":\"")
                    append(module.group.jsonEscape())
                    append("\",\"name\":\"")
                    append(module.module.jsonEscape())
                    append("\",\"version\":\"")
                    append(module.version.jsonEscape())
                    append("\",\"purl\":\"")
                    append(purl.jsonEscape())
                    append("\",\"hashes\":[{\"alg\":\"SHA-256\",\"content\":\"")
                    append(sha256(file))
                    append("\"}],\"properties\":[{\"name\":\"hermes.artifact.file\",\"value\":\"")
                    append(file.name.jsonEscape())
                    append("\"}]}")
                }
                "${purl}|${file.name}" to component
            }
            .distinctBy { it.first }
            .sortedBy { it.first }
            .map { it.second }

        require(entries.isNotEmpty()) {
            "No release runtime dependency artifacts were resolved; refusing to write an empty SBOM."
        }
        releaseSbomReport.get().asFile.apply {
            parentFile.mkdirs()
            writeText(buildString {
                append("{\n")
                append("  \"bomFormat\": \"CycloneDX\",\n")
                append("  \"specVersion\": \"1.5\",\n")
                append("  \"version\": 1,\n")
                append("  \"components\": [\n")
                entries.forEachIndexed { index, entry ->
                    append("    ").append(entry)
                    if (index != entries.lastIndex) append(",")
                    append("\n")
                }
                append("  ]\n}\n")
            })
        }
    }
}

tasks.register("verifyReleaseSbom") {
    dependsOn("generateReleaseSbom")
    doLast {
        val report = releaseSbomReport.get().asFile
        val contents = report.readText()
        require(contents.contains("\"bomFormat\": \"CycloneDX\"")) {
            "The generated release SBOM is missing its CycloneDX format marker."
        }
        require(contents.contains("\"components\": [")) {
            "The generated release SBOM has no components array."
        }
    }
}

tasks.register("verifyReleaseGate") {
    dependsOn(
        "verifyReleaseConfiguration",
        "verifyReleaseSigning",
        "verifyDependencyChecksums",
        "verifyReleaseSbom",
    )
}

tasks.register("writeReleaseChecksum") {
    dependsOn("packageRelease")
    inputs.file(releaseApk)
    outputs.file(releaseApkChecksum)
    doLast {
        val apk = releaseApk.get().asFile
        require(apk.isFile) {
            "Expected release APK was not produced at ${apk.path}."
        }
        releaseApkChecksum.get().asFile.writeText("${sha256(apk)}  ${apk.name}\n")
    }
}

fun locateApksigner(): File? {
    project.providers.gradleProperty("hermes.apksigner").orNull?.takeIf { it.isNotBlank() }?.let { configured ->
        return project.file(configured).takeIf { it.isFile }
    }
    val sdkRoot = System.getenv("ANDROID_SDK_ROOT") ?: System.getenv("ANDROID_HOME") ?: return null
    val buildTools = File(sdkRoot, "build-tools")
    val windows = System.getProperty("os.name").startsWith("Windows", ignoreCase = true)
    val executableName = if (windows) "apksigner.bat" else "apksigner"
    return buildTools.listFiles()
        ?.filter { it.isDirectory && File(it, executableName).isFile }
        ?.maxByOrNull { it.name }
        ?.resolve(executableName)
}

tasks.register("verifyReleaseArtifact") {
    dependsOn("writeReleaseChecksum")
    doLast {
        val apk = releaseApk.get().asFile
        val apksigner = locateApksigner()
            ?: error("Android build-tools apksigner is required. Set -Phermes.apksigner or install the Android SDK build-tools on the release host.")
        val command = if (apksigner.name.endsWith(".bat", ignoreCase = true)) {
            listOf("cmd", "/c", apksigner.absolutePath, "verify", "--verbose", "--print-certs", apk.absolutePath)
        } else {
            listOf(apksigner.absolutePath, "verify", "--verbose", "--print-certs", apk.absolutePath)
        }
        project.exec { commandLine(command) }

        val recorded = releaseApkChecksum.get().asFile.readText().trim()
        require(recorded == "${sha256(apk)}  ${apk.name}") {
            "The release APK checksum changed after the recorded checksum was written."
        }
    }
}

tasks.matching { it.name == "preReleaseBuild" }.configureEach {
    dependsOn("verifyReleaseGate")
}
tasks.matching { it.name == "assembleRelease" }.configureEach {
    dependsOn("verifyReleaseGate")
    finalizedBy("verifyReleaseArtifact")
}

ksp {
    arg("room.schemaLocation", "$projectDir/schemas")
    arg("room.generateKotlin", "true")
}

kapt {
    correctErrorTypes = true
}

dependencies {
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.browser)
    implementation(libs.androidx.biometric)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.ui.tooling.preview)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.material.icons.extended)
    debugImplementation(libs.androidx.compose.ui.tooling)

    implementation(libs.hilt.android)
    kapt(libs.hilt.compiler)
    implementation(libs.androidx.hilt.navigation.compose)
    implementation(libs.androidx.hilt.work)
    kapt(libs.androidx.hilt.compiler)

    implementation(libs.androidx.room.runtime)
    implementation(libs.androidx.room.ktx)
    ksp(libs.androidx.room.compiler)
    implementation(libs.androidx.datastore.preferences)
    implementation(libs.okhttp)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.androidx.work.runtime.ktx)
    implementation(libs.androidx.media3.exoplayer)
    implementation(libs.androidx.media3.ui)
    implementation(libs.firebase.messaging)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.test.runner)
}
