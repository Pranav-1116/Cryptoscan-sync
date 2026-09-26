import javax.net.ssl.*;
public class W2SslContextTls1 {
  SSLContext ctx() throws Exception {
    SSLContext c = SSLContext.getInstance("TLSv1");
    c.init(null, new TrustManager[]{ new X509TrustManager() {
      public void checkClientTrusted(java.security.cert.X509Certificate[] x, String a) {}
      public void checkServerTrusted(java.security.cert.X509Certificate[] x, String a) {}
      public java.security.cert.X509Certificate[] getAcceptedIssuers() { return null; }
    }}, null);
    return c;
  }
}
