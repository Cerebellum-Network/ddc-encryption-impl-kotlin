package network.cere.ddc.crypto.sign

import com.google.crypto.tink.subtle.Hex
import io.emeraldpay.polkaj.schnorrkel.Schnorrkel
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

internal class Sr25519SignerTest {
    private val testSubject =
        Sr25519Signer(Hex.decode("68af9a6071f56544b592f2bb1341f6fbf7cb92722f550df896c69782e860ba420a9efde708d0d1ec5087c8cc632ede9816f7231a7b243e1f63b9255ddcbc3c44"))

    @Test
    fun `Correct algorithm`() {
        //when
        val result = testSubject.algorithm

        //then
        assertEquals(SignatureAlgorithm.SR25519, result)
    }

    @Test
    fun `Sign message`() {
        //given
        val message =
            "someIdsomeTimestamp0x8f01969eb5244d853cc9c6ad73c46d8a1a091842c414cabd2377531f0832635fuserPubKeypiece data"
                .toByteArray()
        val expectedSignatureLength = 128

        //when
        val result = testSubject.signToBytes(message)

        //then
        assertEquals(expectedSignatureLength, Hex.encode(result).length)
        Schnorrkel.getInstance().verify(result, message, Schnorrkel.PublicKey(Hex.decode("fe563a32a5a6e0336e7a7cdb82a5f3a56a7d83c02c7610d2350979086bb4f21c")))
    }
}
