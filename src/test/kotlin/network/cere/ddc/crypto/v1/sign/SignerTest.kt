package network.cere.ddc.crypto.v1.sign

import com.goterl.lazysodium.LazySodiumJava
import com.goterl.lazysodium.SodiumJava
import com.goterl.lazysodium.utils.Key
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

internal class SignerTest {
    private val sodium = LazySodiumJava(SodiumJava())
    private val testSubject =
        Signer(
            sodium,
            "4B4854DD2F6D876FAADBEB7A8AB65259528D5B70F42CD90E39DAEFDB19C4944C79BAACF7D83296DEFFE7266A9E02FD8D522ED1A7100D3BBEC5625DCA1178B6F9"
        )

    @Test
    fun `Sign message`() {
        //given
        val message =
            "someIdsomeTimestamp0x8f01969eb5244d853cc9c6ad73c46d8a1a091842c414cabd2377531f0832635fuserPubKeypiece data"
        val expectedSignature =
            "018699A20F9BF94BAD2A86488BB68CF2E5F1D59EB89592DC534E5A888D3600C1AA1554006003C89B65198980E1C3FC871C9F1C1F49F6F58FC6BBE80623929D0E"

        //when
        val result = testSubject.sign(message)

        //then
        assertEquals(expectedSignature, result)
        assertTrue(
            sodium.cryptoSignVerifyDetached(
                result,
                message,
                Key.fromHexString("79BAACF7D83296DEFFE7266A9E02FD8D522ED1A7100D3BBEC5625DCA1178B6F9")
            )
        )
    }
}
