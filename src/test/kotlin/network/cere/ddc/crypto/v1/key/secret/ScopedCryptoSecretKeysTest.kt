package network.cere.ddc.crypto.v1.key.secret

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

internal class ScopedCryptoSecretKeysTest {
    @Test
    fun `Decrypt JSON with scope keys`() {
        //given
        val scopedCryptoSecretKeys = ScopedCryptoSecretKeys(
            mapOf(
                "$.k1" to "0xb23ca57e91bef84fe2ef3148cae0a128ed52fa30cf8913cf86575d742c9220c4",
                "$.k3.k4" to "0x0dc928985d3f629b660bb4d696d7378d4b93af994a7a0a051a456370c7cca9f2"
            )
        )
        val data = """
            {
                "k1": "0x3be6fb0897423de4d39f3b54d63f35ee089d",
                "k2": "v2",
                "k3": {
                    "k4": "0x4710aa05ca84d14e3c7c4c612daf27cdbd1983e8",
                    "k5": ["v5", "v5"]
                },
                "k6": {
                    "k7": {
                        "k8": "0x51882a2acddd07375c33eacc6f3e17c65c74cc"
                    }
                }
            }
        """.trimIndent()

        //when
        val result = scopedCryptoSecretKeys.decryptWithScopes(data)

        //then
        assertEquals(
            """{"k1":"v1","k2":"v2","k3":{"k4":"true","k5":["v5","v5"]},"k6":{"k7":{"k8":"0x51882a2acddd07375c33eacc6f3e17c65c74cc"}}}""",
            result
        )
    }

    @Test
    fun `Decrypt raw with scope keys`() {
        //given
        val scopedCryptoSecretKeys =
            ScopedCryptoSecretKeys("0x3f4b78db4c57b2a9981226457f3b1c36b9f0ca7b29f0051624129383741ca887")
        val data = "0x581e9480a805f93ab877d0809b5f4a6b9b22eed9b5f7aab0"

        //when
        val result = scopedCryptoSecretKeys.decryptWithScopes(data)

        //then
        assertEquals("raw data", result)
    }
}
