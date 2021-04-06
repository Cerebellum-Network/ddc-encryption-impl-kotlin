package network.cere.ddc.crypto.v1.decrypt

import com.google.crypto.tink.subtle.Hex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

internal class RawDataDecrypterTest {
    @Test
    fun `Decrypt raw`() {
        //given
        val config = DecryptionConfig(
            mapOf("" to Hex.encode("super-secret-key".repeat(2).toByteArray()))
        )
        val decrypter = RawDataDecrypter(config)
        val data =
            Hex.decode("aeafd33394bd45142dec4134e6cb71927634e9b31deed4f725fd5210ce8d65b5f2161cff5701dfe1243009df7576053d")

        //when
        val result = decrypter.decrypt(data)

        //then
        assertEquals("raw data", result.decodeToString())
    }
}
