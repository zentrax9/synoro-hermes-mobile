package com.hermes.mobile.di

import android.content.Context
import androidx.room.Room
import com.hermes.mobile.BuildConfig
import com.hermes.mobile.data.AppPreferencesRepository
import com.hermes.mobile.data.AuthTransactionStore
import com.hermes.mobile.data.HermesAuthSession
import com.hermes.mobile.data.HermesDao
import com.hermes.mobile.data.HermesDatabase
import com.hermes.mobile.data.MIGRATION_1_2
import com.hermes.mobile.data.MIGRATION_2_3
import com.hermes.mobile.data.MIGRATION_3_4
import com.hermes.mobile.data.MIGRATION_4_5
import com.hermes.mobile.data.MIGRATION_5_6
import com.hermes.mobile.data.appPreferencesRepository
import com.hermes.mobile.network.HermesRequestFactory
import com.hermes.mobile.network.NetworkSecurity
import com.hermes.mobile.auth.CustomTabPkceFlow
import com.hermes.mobile.auth.PkceTokenExchange
import com.hermes.mobile.media.VoiceNoteRecorder
import com.hermes.mobile.security.EncryptedValueStore
import com.hermes.mobile.security.HermesKeyStore
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import okhttp3.HttpUrl
import okhttp3.OkHttpClient
import okhttp3.HttpUrl.Companion.toHttpUrl
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {
    @Provides
    @Singleton
    fun provideDatabase(@ApplicationContext context: Context): HermesDatabase =
        Room.databaseBuilder(context, HermesDatabase::class.java, "hermes-cache.db")
            .addMigrations(MIGRATION_1_2)
            .addMigrations(MIGRATION_2_3)
            .addMigrations(MIGRATION_3_4)
            .addMigrations(MIGRATION_4_5)
            .addMigrations(MIGRATION_5_6)
            .build()

    @Provides
    fun provideHermesDao(database: HermesDatabase): HermesDao = database.hermesDao()

    @Provides
    @Singleton
    fun provideKeyStore(): HermesKeyStore = HermesKeyStore()

    @Provides
    @Singleton
    fun provideEncryptedValueStore(): EncryptedValueStore = EncryptedValueStore()

    @Provides
    @Singleton
    fun provideOkHttpClient(): OkHttpClient = NetworkSecurity.newClient()

    @Provides
    @Singleton
    fun provideMobileBaseUrl(): HttpUrl = BuildConfig.MOBILE_BASE_URL.toHttpUrl()

    @Provides
    @Singleton
    fun provideRequestFactory(
        baseUrl: HttpUrl,
        authSession: HermesAuthSession,
    ): HermesRequestFactory = HermesRequestFactory(baseUrl, authProvider = authSession)

    @Provides
    @Singleton
    fun provideCustomTabPkceFlow(
        transactions: AuthTransactionStore,
    ): CustomTabPkceFlow = CustomTabPkceFlow(transactions)

    @Provides
    @Singleton
    fun providePkceTokenExchange(
        httpClient: OkHttpClient,
    ): PkceTokenExchange = PkceTokenExchange(httpClient)

    @Provides
    @Singleton
    fun provideVoiceNoteRecorder(
        @ApplicationContext context: Context,
    ): VoiceNoteRecorder = VoiceNoteRecorder(context.filesDir)

    @Provides
    @Singleton
    fun provideAppPreferencesRepository(
        @ApplicationContext context: Context,
    ): AppPreferencesRepository = context.appPreferencesRepository()
}
