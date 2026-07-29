plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.ksp)
    alias(libs.plugins.hilt)
}

android {
    namespace = "com.tester4real.personalauthenticator"
    compileSdk = 37

    defaultConfig {
        applicationId = "com.tester4real.personalauthenticator"
        minSdk = 28
        targetSdk = 37
        versionCode = 1
        versionName = "1.0.0-dev"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        buildConfigField("String", "GITHUB_OWNER", "\"Tester4Real\"")
        buildConfigField("String", "GITHUB_REPOSITORY", "\"authenticator-sync\"")
        buildConfigField(
            "String",
            "GITHUB_BRANCH",
            "\"personal-authenticator-sync\"",
        )
        buildConfigField(
            "String",
            "GITHUB_PATH",
            "\".personal-authenticator\"",
        )
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    buildFeatures {
        buildConfig = true
        compose = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    packaging {
        resources.excludes += setOf(
            "META-INF/AL2.0",
            "META-INF/LGPL2.1",
            "META-INF/versions/9/OSGI-INF/MANIFEST.MF",
        )
    }

    lint {
        warningsAsErrors = true
        // AGP 9.3.1 embeds Kotlin 2.2.10 and officially defaults to Gradle
        // 9.5.0. Do not mix a newer standalone Compose compiler or wrapper
        // into that tested toolchain merely to satisfy version suggestions.
        disable += setOf(
            "AndroidGradlePluginVersion",
            "NewerVersionAvailable",
        )
    }
}

dependencies {
    implementation(project(":domain"))
    implementation(project(":vault"))
    implementation(project(":sync"))
    implementation(project(":scanner"))

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.navigation.compose)
    implementation(libs.androidx.hilt.navigation.compose)
    implementation(libs.hilt.android)
    implementation(libs.coroutines.android)
    ksp(libs.hilt.compiler)

    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.ui.tooling.preview)
    debugImplementation(libs.androidx.compose.ui.tooling)
    debugImplementation(libs.androidx.compose.ui.test.manifest)

    testImplementation(libs.junit)
    testImplementation(libs.coroutines.test)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.compose.ui.test.junit4)
    androidTestImplementation(libs.androidx.test.runner)
    androidTestImplementation(libs.espresso.core)
}
