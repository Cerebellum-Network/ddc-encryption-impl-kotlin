package network.cere.ddc.crypto

import com.fasterxml.jackson.databind.ObjectMapper
import com.google.crypto.tink.subtle.Hex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

internal class DecrypterTest {
    private val objectMapper = ObjectMapper()
    private val testSubject = Decrypter(objectMapper)

    private val masterKey = "super-secret"
    private val scopeKeys = mapOf(
        "geo_location" to "dd88bb36437495f1ae0f857abb5c0fe33bd17a73ee48da372637dabf40a84d0c",
        "private_info" to "e661a2888f75ca33b9b74cefd2b88559b2ea595da8fc01128a06069d8bab62ae",
        "__default_scope" to "c9ab4a99fbbb89b4e51fffc9b42b80ce50788db93edaa5b3fa991d756b6164e4"
    ).mapValues { Hex.decode(it.value) }

    @Test
    fun `Decrypt JSON with master key`() {
        //given
        val encryptedData = """
            {
                "geo_location":"9a349278dd296d7341ffc874e222f122de2bc010ac5ebc16e3987827f33d6733ef41c02dfeea41be2cf5484761d41a8e3e3c1fb8396223aebe",
                "private_info":"8597e2a6b3afed0c03d55ff4ecee64cf8c8556de5491ccf3d753f01f21bec038fe4b92a0639199da5a4572d6ab545c825fc719371a654e919608fe69a01188a5dddff40ee89caf2addc69d2c40245e7ddb7060365acb4348a5acf814dacf180d4e176b8e12ed08593338cb789830eaed2b64c6",
                "__default_scope":"edbbc40a181b945e6c4033226041a269c8e59dd2c982fb51dea5d5a9f091c5fee3586065d88a2b15552d5af4424dc0e315e4721ff8136c137c"
            }
        """.trimIndent().toByteArray()

        //when
        val result = testSubject.decrypt(encryptedData, masterKey, TypeHint.JSON)

        //then
        assertEquals(
            """{"address":"abc","name":{"first":"John","second":"Doe"},"dob":"09-12-1988","event":"CLICK"}""",
            result.decodeToString()
        )
    }

    @Test
    fun `Decrypt JSON with all scope keys`() {
        //given
        val encryptedData = """
            {
                "geo_location":"9a349278dd296d7341ffc874e222f122de2bc010ac5ebc16e3987827f33d6733ef41c02dfeea41be2cf5484761d41a8e3e3c1fb8396223aebe",
                "private_info":"8597e2a6b3afed0c03d55ff4ecee64cf8c8556de5491ccf3d753f01f21bec038fe4b92a0639199da5a4572d6ab545c825fc719371a654e919608fe69a01188a5dddff40ee89caf2addc69d2c40245e7ddb7060365acb4348a5acf814dacf180d4e176b8e12ed08593338cb789830eaed2b64c6",
                "__default_scope":"edbbc40a181b945e6c4033226041a269c8e59dd2c982fb51dea5d5a9f091c5fee3586065d88a2b15552d5af4424dc0e315e4721ff8136c137c"
            }
        """.trimIndent().toByteArray()

        //when
        val result = testSubject.decrypt(encryptedData, scopeKeys, TypeHint.JSON)

        //then
        assertEquals(
            """{"address":"abc","name":{"first":"John","second":"Doe"},"dob":"09-12-1988","event":"CLICK"}""",
            result.decodeToString()
        )
    }

    @Test
    fun `Decrypt JSON with single scope key`() {
        //given
        val encryptedData = """
            {
                "geo_location":"9a349278dd296d7341ffc874e222f122de2bc010ac5ebc16e3987827f33d6733ef41c02dfeea41be2cf5484761d41a8e3e3c1fb8396223aebe",
                "private_info":"8597e2a6b3afed0c03d55ff4ecee64cf8c8556de5491ccf3d753f01f21bec038fe4b92a0639199da5a4572d6ab545c825fc719371a654e919608fe69a01188a5dddff40ee89caf2addc69d2c40245e7ddb7060365acb4348a5acf814dacf180d4e176b8e12ed08593338cb789830eaed2b64c6",
                "__default_scope":"edbbc40a181b945e6c4033226041a269c8e59dd2c982fb51dea5d5a9f091c5fee3586065d88a2b15552d5af4424dc0e315e4721ff8136c137c"
            }
        """.trimIndent().toByteArray()

        //when
        val result = testSubject.decrypt(encryptedData, scopeKeys.filterKeys { it == "geo_location" }, TypeHint.JSON)

        //then
        assertEquals("""{"address":"abc"}""", result.decodeToString())
    }

    @Test
    fun `Decrypt raw with master key`() {
        //given
        val encryptedData = """
            {"__default_scope":"7fd7abf981e2785c4e22b46c35e1e76b5be3b139afa80a8fcb7270db10b7c96b34b2c364107822612a0dd1"}
        """.trimIndent().toByteArray()

        //when
        val result = testSubject.decrypt(encryptedData, masterKey, TypeHint.RAW)

        //then
        assertEquals("""abc""", result.decodeToString())
    }

    @Test
    fun `Decrypt raw with scope keys`() {
        //given
        val encryptedData = """
            {"__default_scope":"7fd7abf981e2785c4e22b46c35e1e76b5be3b139afa80a8fcb7270db10b7c96b34b2c364107822612a0dd1"}
        """.trimIndent().toByteArray()

        //when
        val result = testSubject.decrypt(encryptedData, scopeKeys.filterKeys { it == "__default_scope" }, TypeHint.RAW)

        //then
        assertEquals("abc", String(result))
    }

    @Test
    fun `Decrypt raw with multiple scopes`() {
        //given
        val encryptedData = """
            {
                "geo_location":"9a349278dd296d7341ffc874e222f122de2bc010ac5ebc16e3987827f33d6733ef41c02dfeea41be2cf5484761d41a8e3e3c1fb8396223aebe",
                "private_info":"8597e2a6b3afed0c03d55ff4ecee64cf8c8556de5491ccf3d753f01f21bec038fe4b92a0639199da5a4572d6ab545c825fc719371a654e919608fe69a01188a5dddff40ee89caf2addc69d2c40245e7ddb7060365acb4348a5acf814dacf180d4e176b8e12ed08593338cb789830eaed2b64c6",
                "__default_scope":"edbbc40a181b945e6c4033226041a269c8e59dd2c982fb51dea5d5a9f091c5fee3586065d88a2b15552d5af4424dc0e315e4721ff8136c137c"
            }
        """.trimIndent().toByteArray()

        //when
        val result = testSubject.decrypt(encryptedData, masterKey, TypeHint.RAW)

        //then
        assertEquals(
            """{"address":"abc"}{"name":{"first":"John","second":"Doe"},"dob":"09-12-1988","address":"abc"}{"event":"CLICK"}""",
            result.decodeToString()
        )
    }

    @Test
    fun `Decrypt unknown data with single scope`() {
        //given
        val encryptedData = """
            {"__default_scope":"0bd40fb99aef9fcfb5278d5d04b7c60333cb933fa4d39cc12ac355674216d5234e0f9c7eee9c0caf7d314fddbeaf22a037c6edaee0e826fec0"}
        """.trimIndent().toByteArray()

        //when
        val result = testSubject.decrypt(encryptedData, masterKey)

        //then
        assertEquals("""{"event":"CLICK"}""", result.decodeToString())
    }

    @Test
    fun `Decrypt unknown data with multiple scopes (JSON)`() {
        //given
        val encryptedData = """
            {
                "geo_location":"9a349278dd296d7341ffc874e222f122de2bc010ac5ebc16e3987827f33d6733ef41c02dfeea41be2cf5484761d41a8e3e3c1fb8396223aebe",
                "private_info":"8597e2a6b3afed0c03d55ff4ecee64cf8c8556de5491ccf3d753f01f21bec038fe4b92a0639199da5a4572d6ab545c825fc719371a654e919608fe69a01188a5dddff40ee89caf2addc69d2c40245e7ddb7060365acb4348a5acf814dacf180d4e176b8e12ed08593338cb789830eaed2b64c6",
                "__default_scope":"edbbc40a181b945e6c4033226041a269c8e59dd2c982fb51dea5d5a9f091c5fee3586065d88a2b15552d5af4424dc0e315e4721ff8136c137c"
            }
        """.trimIndent().toByteArray()

        //when
        val result = testSubject.decrypt(encryptedData, masterKey)

        //then
        assertEquals(
            """{"address":"abc","name":{"first":"John","second":"Doe"},"dob":"09-12-1988","event":"CLICK"}""",
            result.decodeToString()
        )
    }
}
