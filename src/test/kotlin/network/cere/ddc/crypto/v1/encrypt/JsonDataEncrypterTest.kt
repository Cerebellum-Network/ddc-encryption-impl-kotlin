package network.cere.ddc.crypto.v1.encrypt

import com.google.crypto.tink.subtle.Hex
import com.jayway.jsonpath.JsonPath
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

internal class JsonDataEncrypterTest {
    private val masterKeyHex = Hex.encode("super-secret-key".repeat(2).toByteArray())

    @Test
    fun `Encrypt all fields in JSON`() {
        //given
        val config = EncryptionConfig(masterKeyHex)
        val encrypter = JsonDataEncrypter(config)
        val data = """
            {
                "k1": "v1",
                "k2": "v2",
                "k3": {
                    "k4": true,
                    "k5": ["v5", "v5"]
                },
                "k6": {
                    "k7": {
                        "k8": 123
                    }
                }
            }
        """.trimIndent().toByteArray()

        //when
        val result = encrypter.encrypt(data)

        //then
        val ctx = result.inputStream().use(JsonPath::parse)
        val values = ctx.read<List<Any>>("$..*").filterIsInstance<String>()
        assertEquals(6, values.size)
        values.forEach { assertTrue(it.length > 64) }
    }

    @Test
    fun `Encrypt some fields in JSON`() {
        //given
        val config = EncryptionConfig(masterKeyHex, listOf("$.k3..*"))
        val encrypter = JsonDataEncrypter(config)
        val data = """
            {
                "k1": "v1",
                "k2": "v2",
                "k3": {
                    "k4": true,
                    "k5": ["v5", "v5"]
                },
                "k6": {
                    "k7": {
                        "k8": 123
                    }
                }
            }
        """.trimIndent().toByteArray()

        //when
        val result = encrypter.encrypt(data)

        //then
        val ctx = result.inputStream().use(JsonPath::parse)
        val values = ctx.read<List<Any>>("$..*").filter { it is String || it is Number }
        assertEquals(6, values.size)
        assertEquals("v1", values[0])
        assertEquals("v2", values[1])
        assertNotEquals("true", values[2])
        assertNotEquals("v5", values[3])
        assertNotEquals("v5", values[4])
        assertEquals(123, values[5])
    }
}
