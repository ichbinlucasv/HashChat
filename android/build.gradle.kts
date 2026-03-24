plugins {
    id("com.android.application")
}
android {
    namespace = "chat.hashchat"
    compileSdk = 34
    defaultConfig {
        applicationId = "chat.hashchat"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.9"
    }
}
dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
}