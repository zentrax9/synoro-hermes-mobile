package com.hermes.mobile.network

import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import java.io.IOException

object NetworkSecurity {
    fun newClient(): OkHttpClient = OkHttpClient.Builder()
        .connectionSpecs(listOf(ConnectionSpec.MODERN_TLS))
        .followRedirects(false)
        .followSslRedirects(false)
        .addInterceptor { chain ->
            val request = chain.request()
            if (request.url.scheme != "https") {
                throw IOException("cleartext HTTP is disabled for Hermes mobile")
            }
            chain.proceed(request)
        }
        .build()
}
