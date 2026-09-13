package com.hermes.mobile.contract

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.encodeToJsonElement
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class ContractModelsTest {
    @Test
    fun canonicalIdsRejectPathsAndPreserveInstanceBoundary() {
        assertThrows(IllegalArgumentException::class.java) {
            BotId("instance-01", "../profile")
        }
        val bot = BotId("instance-01", "profile-01")
        assertEquals("instance-01", bot.instanceId)
        assertEquals("profile-01", bot.opaqueProfileId)
    }

    @Test
    fun sealedMessagePartsUseStableWireDiscriminators() {
        val json = Json { encodeDefaults = true }
        val encoded = json.encodeToJsonElement(MessagePart.serializer(), MessagePart.Text("hello"))
        assertEquals("text", encoded.jsonObject["type"]?.jsonPrimitive?.content)
        assertNotNull(encoded.jsonObject["text"])
    }

    @Test
    fun linkPolicyAllowsHttpAndHttpsOnlyWithoutCredentials() {
        assertTrue(LinkPolicy.normalizeExternalUrl("https://example.com/a")!!.startsWith("https://"))
        assertTrue(LinkPolicy.normalizeExternalUrl("http://example.com/a")!!.startsWith("http://"))
        assertEquals(null, LinkPolicy.normalizeExternalUrl("javascript:alert(1)"))
        assertEquals(null, LinkPolicy.normalizeExternalUrl("https://user:pass@example.com/a"))
        assertEquals(null, LinkPolicy.normalizeExternalUrl("https://example.com/a\u0000b"))
        assertEquals(
            null,
            LinkPolicy.normalizeExternalUrl("https://example.com/".padEnd(LinkPolicy.MAX_EXTERNAL_URL_LENGTH + 1, 'x')),
        )
    }
}
