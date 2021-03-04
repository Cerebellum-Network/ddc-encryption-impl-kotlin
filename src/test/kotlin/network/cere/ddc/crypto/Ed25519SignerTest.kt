package network.cere.ddc.crypto

import com.google.crypto.tink.subtle.Ed25519Verify
import com.google.crypto.tink.subtle.Hex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

internal class Ed25519SignerTest {
    private val testSubject =
        Ed25519Signer(Hex.decode("38a538d3d890bfe8f76dc9bf578e215af16fd3d684666f72db0bc0a22bc1d05b"))

    @Test
    fun `Sign message`() {
        //given
        val message =
            "someIdsomeTimestamp0x8f01969eb5244d853cc9c6ad73c46d8a1a091842c414cabd2377531f0832635fuserPubKeypiece data"
                .toByteArray()
        val expectedSignature =
            "0cc8f3b637e28c07074b8c114c4628155f7ff666c9554561772149e5b06ed17274095d0b0bf2eabf5c5b2a670f60b1bced914437e5aaf74fb729e78830362709"

        //when
        val result = testSubject.sign(message)

        //then
        assertEquals(expectedSignature, Hex.encode(result))
        Ed25519Verify(Hex.decode("8f01969eb5244d853cc9c6ad73c46d8a1a091842c414cabd2377531f0832635f"))
            .verify(result, message)
    }
}
