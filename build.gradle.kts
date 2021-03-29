import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.4.30"
    maven
}

group = "com.github.cerebellum-network"

repositories {
    mavenLocal()
    mavenCentral()
    maven { url = uri("https://dl.bintray.com/emerald/polkaj") }
}

dependencies {
    implementation(kotlin("stdlib"))

    implementation("com.rfksystems:blake2b:1.0.0")
    implementation("com.google.crypto.tink:tink:1.5.0")
    implementation("io.emeraldpay.polkaj:polkaj-schnorrkel:0.3.0")

    implementation("com.fasterxml.jackson.core:jackson-databind:2.12.1")

    testImplementation(platform("org.junit:junit-bom:5.7.1"))
    testImplementation("org.junit.jupiter:junit-jupiter")
}

tasks {
    withType<KotlinCompile> {
        kotlinOptions {
            jvmTarget = JavaVersion.VERSION_11.toString()
            javaParameters = true
        }
    }

    withType<Test> {
        useJUnitPlatform()
    }
}
