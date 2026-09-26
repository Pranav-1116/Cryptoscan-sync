package sa.com.bank.mobile.net

import okhttp3.CertificatePinner
import okhttp3.ConnectionSpec
import okhttp3.OkHttpClient
import okhttp3.TlsVersion

/** تثبيت الشهادات لواجهات الخدمات المصرفية (بصمة SPKI SHA-256) */
object PinnedClient {
    fun build(): OkHttpClient = OkHttpClient.Builder()
        .certificatePinner(CertificatePinner.Builder()
            .add("api.alahli.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .add("api.alahli.com", "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
            .build())
        .connectionSpecs(listOf(ConnectionSpec.Builder(ConnectionSpec.RESTRICTED_TLS)
            .tlsVersions(TlsVersion.TLS_1_3, TlsVersion.TLS_1_2).build()))
        .build()
}
