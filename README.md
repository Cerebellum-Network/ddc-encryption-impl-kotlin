# DDC Encryption Module Kotlin implementation

Kotlin implementation of DDC encryption and decryption algorithms.

## Requirements

This library requires Java version 11 or higher and Kotlin version 1.4 or higher.

## Usage

Add dependency in your Gradle build script:

```kotlin
repositories {
    maven { url = uri("https://jitpack.io") }
}
dependencies {
    implementation("com.github.cerebellum-network:ddc-encryption-impl-kotlin:1.0.0")
}
```

```kotlin
// Create instances
private val objectMapper = ObjectMapper()
private val encrypter = Encrypter(
    objectMapper,
    EncryptionConfig(
        "super-secret", listOf(
            EncryptionConfig.Scope("geo_location", listOf("geo_location", "address")),
            EncryptionConfig.Scope("private_info", listOf("name", "dob", "address"))
        )
    )
)
private val decrypter = Decrypter(objectMapper)

// Encrypt and decrypt JSON
val json = """{"address":"abc","name":{"first":"John","second":"Doe"},"dob":"09-12-1988","event":"CLICK"}""".toByteArray()
var encrypted = encrypter.encrypt(json)

// {
//    "geo_location":"9a349278dd296d7341ffc874e222f122de2bc010ac5ebc16e3987827f33d6733ef41c02dfeea41be2cf5484761d41a8e3e3c1fb8396223aebe",
//    "private_info":"8597e2a6b3afed0c03d55ff4ecee64cf8c8556de5491ccf3d753f01f21bec038fe4b92a0639199da5a4572d6ab545c825fc719371a654e919608fe69a01188a5dddff40ee89caf2addc69d2c40245e7ddb7060365acb4348a5acf814dacf180d4e176b8e12ed08593338cb789830eaed2b64c6",
//    "__default_scope":"edbbc40a181b945e6c4033226041a269c8e59dd2c982fb51dea5d5a9f091c5fee3586065d88a2b15552d5af4424dc0e315e4721ff8136c137c"
// }

var decrypted = decrypter.decrypt(encrypted, encrypter.scopeToKey, TypeHint.JSON)

//{"address":"abc","name":{"first":"John","second":"Doe"},"dob":"09-12-1988","event":"CLICK"}

// Encrypt and decrypt raw data
val data = "abc".toByteArray()
encrypted = encrypter.encrypt(data)

// {"__default_scope":"7fd7abf981e2785c4e22b46c35e1e76b5be3b139afa80a8fcb7270db10b7c96b34b2c364107822612a0dd1"}

decrypted = decrypter.decrypt(encrypted, encrypter.scopeToKey, TypeHint.RAW)

// abc
```
