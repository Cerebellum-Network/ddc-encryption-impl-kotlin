import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("jvm") version "1.4.30"
    maven
    jacoco
}

group = "com.github.cerebellum-network"

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib"))

    api("com.goterl:lazysodium-java:5.0.1")
    implementation("net.java.dev.jna:jna:5.8.0")

    implementation("com.github.jsurfer:jsurfer-jackson:1.6.0")
    implementation("com.jayway.jsonpath:json-path:2.5.0")

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
        finalizedBy(jacocoTestReport)
    }

    withType<JacocoReport> {
        reports {
            xml.isEnabled = true
            html.isEnabled = false
        }
    }
}
