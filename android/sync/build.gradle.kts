plugins {
    alias(libs.plugins.android.library)
    alias(libs.plugins.ksp)
    alias(libs.plugins.hilt)
}

android {
    namespace = "com.tester4real.personalauthenticator.sync"
    compileSdk = 37

    defaultConfig {
        minSdk = 28
        consumerProguardFiles("consumer-rules.pro")
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
    api(project(":domain"))
    implementation(project(":vault"))
    implementation(libs.okhttp)
    implementation(libs.moshi)
    implementation(libs.androidx.work.runtime)
    implementation(libs.hilt.work)
    implementation(libs.hilt.android)
    implementation(libs.coroutines.android)
    ksp(libs.moshi.codegen)
    ksp(libs.hilt.compiler)
    ksp(libs.hilt.work.compiler)

    testImplementation(libs.junit)
    testImplementation(libs.coroutines.test)
}
