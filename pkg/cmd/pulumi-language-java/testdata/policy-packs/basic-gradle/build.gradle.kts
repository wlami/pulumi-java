plugins {
    `java`
}

repositories {
    mavenLocal()
    mavenCentral()
}

dependencies {
    implementation("com.pulumi:pulumi-policy:0.1.0-SNAPSHOT")
}

java {
    sourceCompatibility = JavaVersion.VERSION_11
    targetCompatibility = JavaVersion.VERSION_11
}
