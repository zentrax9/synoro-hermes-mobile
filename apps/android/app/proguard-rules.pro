# Hermes mobile serializes sealed API contracts by their explicit @SerialName values.
# Keep generated serializers and Room entities when shrinking release builds.
-keep class com.hermes.mobile.contract.**$$serializer { *; }
-keep class com.hermes.mobile.auth.**$$serializer { *; }
-keep class com.hermes.mobile.security.**$$serializer { *; }
-keepclassmembers class com.hermes.mobile.contract.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep class com.hermes.mobile.data.** { *; }
