package network.cere.ddc.crypto.v1.key.secret

import network.cere.ddc.crypto.v1.toHex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

internal class CryptoSecretKeyTest {
    private val masterKey = CryptoSecretKey("super-secret".toByteArray())

    @Test
    fun `Derive key`() {
        //given
        val path = "$"

        //when
        val derivedKey = masterKey.derive(path)

        //then
        assertEquals("0x18bbe83a52beab7a8dc17287613bfdebfe76128c69fa64a6c878515570b26816", derivedKey.toHex())
    }

    @Test
    fun `Encrypt all fields in JSON`() {
        //given
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
        """.trimIndent()

        //when
        val result = masterKey.encryptWithScopes(data)

        //then
        assertEquals(
            """{"k1":"0x2db8c357ae04d19429e6d23653f7a6ea309c","k2":"0xec901437e6b92cafc53bef3621456fcffe91","k3":{"k4":"0x2858640a3c7ac24672a9939f8908c348407305d5","k5":["0x2c715eca6aaa71116546e141ea806f16d936","0x50acfe925e07ac3e75060b85e1d67e2c5e09"]},"k6":{"k7":{"k8":"0xf3222430dad86f3abb8ca45ff16d3f5edb87f6"}}}""",
            result.encryptedData
        )
    }

    @Test
    fun `Encrypt some fields in JSON`() {
        //given
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
        """.trimIndent()

        //when
        val result = masterKey.encryptWithScopes(data, listOf("$.k3..*"))

        //then
        assertEquals(
            """{"k1":"v1","k2":"v2","k3":{"k4":"0x2858640a3c7ac24672a9939f8908c348407305d5","k5":["0x2c715eca6aaa71116546e141ea806f16d936","0x50acfe925e07ac3e75060b85e1d67e2c5e09"]},"k6":{"k7":{"k8":123}}}""",
            result.encryptedData
        )
    }

    @Test
    fun `Encrypt raw data`() {
        //given
        val data = "raw data"

        //when
        val result = masterKey.encryptWithScopes(data)

        //then
        assertEquals("0x0a5bf15c177ef4facbc154746b55d3d1ee89cfc5f2e05b7b", result.encryptedData)
    }

    @Test
    fun `Decrypt JSON with master key`() {
        //given
        val data = """
            {
                "k1": "0x2db8c357ae04d19429e6d23653f7a6ea309c",
                "k2": "v2",
                "k3": {
                    "k4": "0x2858640a3c7ac24672a9939f8908c348407305d5",
                    "k5": ["v5", "v5"]
                },
                "k6": {
                    "k7": {
                        "k8": "0xf3222430dad86f3abb8ca45ff16d3f5edb87f6"
                    }
                }
            }
        """.trimIndent()

        //when
        val result = masterKey.decryptWithScopes(data, listOf("$.k1", "$.k3.k4", "$.k6.k7.k8"))

        //then
        assertEquals(
            """{"k1":"v1","k2":"v2","k3":{"k4":"true","k5":["v5","v5"]},"k6":{"k7":{"k8":"123"}}}""",
            result
        )
    }

    @Test
    fun `Decrypt raw with master key`() {
        //given
        val data = "0x0a5bf15c177ef4facbc154746b55d3d1ee89cfc5f2e05b7b"

        //when
        val result = masterKey.decryptWithScopes(data)

        //then
        assertEquals("raw data", result)
    }
}
