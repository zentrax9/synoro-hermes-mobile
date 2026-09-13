package com.hermes.mobile.data

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Client-side allowlist for the two settings mutation surfaces exposed by the mobile API.
 *
 * The host remains authoritative for values and policy, but rejecting a field-class mismatch
 * locally prevents a UI bug from accidentally routing a sensitive change through the safe
 * endpoint (or from requesting a step-up for a field that is safe to edit).
 */
object SettingsChangePolicy {
    private val safeFields = setOf(
        "display_name",
        "title",
        "avatar",
        "notification_preferences",
        "privacy_preferences",
        "approval_policy",
    )
    private val sensitiveFields = setOf("persona", "model", "provider", "reasoning", "skills")

    fun requireSafe(changes: JsonObject) {
        require(changes.isNotEmpty()) { "settings changes must not be empty" }
        require(changes.keys.all(safeFields::contains)) { "sensitive setting in safe mutation" }
        changes["display_name"]?.let { requireText(it, 256, "display_name") }
        changes["title"]?.let { requireText(it, 256, "title") }
        changes["avatar"]?.let { requireText(it, 256, "avatar") }
        changes["notification_preferences"]?.let {
            require(it is JsonObject) { "notification_preferences must be an object" }
        }
        changes["privacy_preferences"]?.let {
            require(it is JsonObject) { "privacy_preferences must be an object" }
        }
        changes["approval_policy"]?.let {
            require(it is JsonObject) { "approval_policy must be an object" }
        }
    }

    fun requireSensitive(changes: JsonObject) {
        require(changes.isNotEmpty()) { "settings changes must not be empty" }
        require(changes.keys.all(sensitiveFields::contains)) {
            "safe setting in sensitive mutation"
        }
        changes["persona"]?.let { requireText(it, 16_384, "persona") }
        changes["model"]?.let { requireText(it, 256, "model") }
        changes["provider"]?.let { requireText(it, 256, "provider") }
        changes["reasoning"]?.let { requireText(it, 32, "reasoning") }
        changes["skills"]?.let { value ->
            require(value is JsonArray) { "skills must be an array" }
            require(value.all { item -> item is JsonPrimitive && item.isString }) {
                "skills must contain strings"
            }
            require(value.size <= 128) { "too many skills" }
        }
    }

    private fun requireText(value: kotlinx.serialization.json.JsonElement, maxLength: Int, field: String) {
        require(value is JsonPrimitive && value.isString) { "$field must be a string" }
        require(value.content.length <= maxLength) { "$field is too long" }
        require(value.content.none { it.isISOControl() }) { "$field contains a control character" }
    }
}
