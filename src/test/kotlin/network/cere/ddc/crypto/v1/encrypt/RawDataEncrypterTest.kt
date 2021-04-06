package network.cere.ddc.crypto.v1.encrypt

import com.google.crypto.tink.subtle.Hex
import com.google.crypto.tink.subtle.XChaCha20Poly1305
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

internal class RawDataEncrypterTest {
    private val masterKeyHex = Hex.encode("super-secret-key".repeat(2).toByteArray())

    @Test
    fun `Encrypt raw data`() {
        //given
        val config = EncryptionConfig(masterKeyHex)
        val encrypter = RawDataEncrypter(config)
        val data = "raw data".toByteArray()

        //when
        val result = encrypter.encrypt(data)

        //then
        assertEquals(48, result.size)
        val decrypted = XChaCha20Poly1305(Hex.decode(masterKeyHex)).decrypt(result, null)
        assertArrayEquals(data, decrypted)
    }
}
