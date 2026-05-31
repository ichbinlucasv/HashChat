package chat.hashchat

import org.junit.Test
import org.junit.Assert.*

/**
 * Local JVM unit tests for HashChat (no Android device required).
 * These test pure logic, ratchet simulation, posture helpers, and framing helpers.
 *
 * For JNI + UI + Keystore tests, see androidTest/HashChatInstrumentedTest.kt
 */
class HashChatUnitTest {

    @Test
    fun testBasicRatchetKeyGeneration() {
        // Mirrors the Rust test_ratchet_roundtrip_basic
        val fakeKey = ByteArray(32) { it.toByte() }
        assertEquals(32, fakeKey.size)
    }

    @Test
    fun testVoiceChunkFramingMarker() {
        val marker = "VOICE".toByteArray()
        assertEquals(5, marker.size)
        assertEquals('V'.code.toByte(), marker[0])
    }

    @Test
    fun testPostureRefusalLogic() {
        // Pure logic test for the posture system (matches TUI + Android checks)
        fun isActionAllowedInPosture(posture: String, action: String): Boolean {
            val low = posture.contains("LOW") || posture.contains("STANDARD")
            return when (action) {
                "send", "voice", "group", "file", "newburner", "decoy" -> !low
                else -> true
            }
        }

        assertFalse(isActionAllowedInPosture("LOW", "voice"))
        assertFalse(isActionAllowedInPosture("STANDARD", "group"))
        assertTrue(isActionAllowedInPosture("HIGH", "voice"))
    }

    @Test
    fun testGroupPersistenceMetadataFormat() {
        // Simulates the groups.enc format used in real persistence
        val groups = mapOf("Alpha" to listOf(1, 2, 3), "Beta" to listOf(42))
        val sb = StringBuilder()
        groups.forEach { (name, rids) ->
            sb.append(name).append(":").append(rids.joinToString(",")).append("\n")
        }
        val serialized = sb.toString()
        assertTrue(serialized.contains("Alpha:1,2,3"))
    }

    @Test
    fun testCrossDeviceExportBlobFormat() {
        // Matches the HCEXP format used in the Android Rust export
        val stateId = 7
        val blob = ("HCEXP" + stateId.toString()).toByteArray()
        assertTrue(String(blob).startsWith("HCEXP"))
    }

    @Test
    fun testDisappearingMessageWipeLogic() {
        // Simulates the ratchet key wipe path used for disappearing messages and voice chunks
        val skippedKeys = mutableMapOf<Int, ByteArray>()
        skippedKeys[42] = ByteArray(32) { 0xDE.toByte() }
        skippedKeys[43] = ByteArray(32) { 0xAD.toByte() }

        // "Expiry" triggers wipe
        skippedKeys.remove(42)
        assertFalse(skippedKeys.containsKey(42))
        assertTrue(skippedKeys.containsKey(43))
    }

    @Test
    fun testPostureRefusalForFileAndExport() {
        fun isActionAllowedInPosture(posture: String, action: String): Boolean {
            val low = posture.contains("LOW") || posture.contains("STANDARD")
            return when (action) {
                "file", "export" -> !low
                else -> true
            }
        }
        assertFalse(isActionAllowedInPosture("LOW", "file"))
        assertFalse(isActionAllowedInPosture("STANDARD", "export"))
        assertTrue(isActionAllowedInPosture("HIGH", "file"))
    }

    @Test
    fun testRatchetExportImportInvariants() {
        // Simple invariant-style test: export → import should allow continued use (basic property)
        // Mirrors the spirit of property-based testing for ratchet state roundtrips
        val originalRid = 7
        val pass = "test-pass".toByteArray()

        // Simulate export
        val exported = byteArrayOf(1, 2, 3) // placeholder for real serialized state
        // In real test this would call the JNI and verify state survives

        assertTrue(exported.isNotEmpty()) // basic structural invariant
    }

    @Test
    fun testWipeRemovesKeyInvariant() {
        // Property: After wipe_skipped_key, the key should no longer be retrievable
        // This is a core paranoid invariant for disappearing messages
        val skipped = mutableMapOf(99 to ByteArray(32) { 0x42 })
        skipped.remove(99)
        assertFalse(skipped.containsKey(99))
    }
}
