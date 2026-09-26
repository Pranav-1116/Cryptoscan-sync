"""Wave 10 — bank middleware and the remaining mainframe/HSM gaps: IBM MQ (MQSC,
mqclient.ini, JMS), WebSphere (security.xml, ssl.client.props, Liberty server.xml),
WebLogic config.xml / properties, java.security provider order, IBM JSSE2/JCE
quirks, Mule / Camel XML, CXF / Rampart / WSO2, QuickFIX session config, SWIFT
LAU, Thales payShield host commands in a Java HSM client, PL/I calling ICSF.
NOT blind (rules written in the same session); labels written before the first run.

Conventions: MQ CipherSpec -> TLS + cipher + digest (+ RSA/ECDSA for the key
exchange family); provider-order lines -> UNKNOWN (not counted) unless the
provider is a TLS provider (TLS) or algorithm-specific (SunEC -> ECDSA);
payShield PIN/key commands -> 3DES, EI/EK RSA commands -> RSA; keystores -> X509.
"""
from __future__ import annotations


def register(_c) -> None:  # noqa: C901
    # ---------------------------------------------------------------- IBM MQ
    _c("config", "w10_mq_channels.mqsc", """
DEFINE CHANNEL('BANK.SVRCONN') CHLTYPE(SVRCONN) TRPTYPE(TCP) +
       SSLCIPH(TLS_RSA_WITH_AES_256_CBC_SHA256) SSLCAUTH(REQUIRED) +
       SSLPEER('CN=payments,O=Bank') REPLACE
DEFINE CHANNEL('LEGACY.SVRCONN') CHLTYPE(SVRCONN) TRPTYPE(TCP) SSLCIPH(TRIPLE_DES_SHA_US)
ALTER QMGR SSLKEYR('/var/mqm/qmgrs/BANK/ssl/key') CERTLABL('ibmwebspheremqbank')
ALTER CHANNEL('TO.SWIFT') CHLTYPE(SDR) SSLCIPH(ECDHE_RSA_AES_256_GCM_SHA384)
""", {"TLS", "AES", "SHA-256", "RSA", "3DES", "SHA-1", "X509", "SHA-384", "ECDH"})
    _c("config", "w10_mqclient.ini", """
[SSL]
   SSLKeyRepository=/opt/mqm/ssl/clientkey
   CertificateLabel=ibmwebspheremqapp
   SSLCipherSpec=ANY_TLS12_OR_HIGHER
   SSLFipsRequired=YES
[CHANNELS]
   ServerConnectionParms=BANK.SVRCONN/TCP/mq.bank.local(1414)
""", {"X509", "TLS"})
    _c("config", "w10_mq_jms.xml", """
<jmsConnectionFactory jndiName="jms/BankCF">
  <properties.wmqJms queueManager="BANK" hostName="mq.bank.local" port="1414"
      channel="BANK.SVRCONN" transportType="CLIENT"
      sslCipherSuite="TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256" sslFipsRequired="false"/>
</jmsConnectionFactory>
<config-property>
  <config-property-name>sslCipherSuite</config-property-name>
  <config-property-type>java.lang.String</config-property-type>
  <config-property-value>ECDHE_ECDSA_AES_256_GCM_SHA384</config-property-value>
</config-property>
""", {"TLS", "AES", "SHA-384", "ECDSA", "SHA-256", "ECDH", "RSA"})
    _c("java", "w10_MqClient.java", """
import com.ibm.mq.MQEnvironment;
import com.ibm.mq.MQQueueManager;
import com.ibm.mq.constants.CMQC;
public class MqClient {
    void connect() throws Exception {
        MQEnvironment.hostname = "mq.bank.local";
        MQEnvironment.channel = "BANK.SVRCONN";
        MQEnvironment.sslCipherSuite = "TLS_RSA_WITH_AES_128_CBC_SHA256";
        MQEnvironment.sslFipsRequired = true;
        MQQueueManager qm = new MQQueueManager("BANK");
    }
}
""", {"TLS", "AES", "SHA-256", "RSA"})  # convention: suite strings decompose
    _c("java", "w10_MqJms.java", """
import com.ibm.msg.client.jms.JmsConnectionFactory;
import com.ibm.msg.client.jms.JmsFactoryFactory;
import com.ibm.msg.client.wmq.WMQConstants;
public class MqJms {
    JmsConnectionFactory cf(JmsFactoryFactory ff) throws Exception {
        JmsConnectionFactory cf = ff.createConnectionFactory();
        cf.setStringProperty(WMQConstants.WMQ_SSL_CIPHER_SUITE, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384");
        cf.setStringProperty(WMQConstants.WMQ_SSL_PEER_NAME, "CN=BANK");
        return cf;
    }
}
""", {"TLS", "AES", "SHA-384", "ECDH", "ECDSA"})
    # ------------------------------------------------------------ WebSphere
    _c("config", "w10_was_security.xml", """
<security:Security xmi:version="2.0" enabled="true" cacheTimeout="600" issuePermissionWarning="true">
  <repertoire xmi:id="SSLConfig_1" alias="NodeDefaultSSLSettings" type="JSSE">
    <setting xmi:id="SecureSocketLayer_1" clientAuthentication="false" securityLevel="HIGH"
        enabledCiphers="SSL_ECDHE_RSA_WITH_AES_256_GCM_SHA384 SSL_RSA_WITH_3DES_EDE_CBC_SHA"
        jsseProvider="IBMJSSE2" sslProtocol="TLSv1.2" keyStore="KeyStore_1" trustStore="KeyStore_2"/>
  </repertoire>
  <keyStores xmi:id="KeyStore_1" name="NodeDefaultKeyStore" password="{xor}CDo9Hgw=" provider="IBMJCE"
      location="${CONFIG_ROOT}/key.p12" type="PKCS12" fileBased="true"/>
  <keyStores xmi:id="KeyStore_3" name="RACFKeyring" location="safkeyringhw:///BankRing" type="JCERACFKS"/>
  <ltpa xmi:id="LTPA_1" timeout="120" password="{xor}Lz4sLCgwLTs="/>
</security:Security>
""", {"TLS", "AES", "SHA-384", "3DES", "SHA-1", "X509", "ECDH", "RSA", "TLS"})
    _c("config", "w10_ssl.client.props", """
com.ibm.ssl.protocol=TLSv1.2
com.ibm.ssl.keyStoreType=PKCS12
com.ibm.ssl.keyStore=${user.root}/etc/key.p12
com.ibm.ssl.trustStoreType=PKCS12
com.ibm.ssl.enabledCipherSuites=SSL_ECDHE_RSA_WITH_AES_128_GCM_SHA256 SSL_RSA_WITH_RC4_128_SHA
com.ibm.ssl.securityLevel=HIGH
""", {"TLS", "X509", "AES", "SHA-256", "RC4", "SHA-1", "ECDH", "RSA", "TLS"})
    _c("config", "w10_liberty_server.xml", """
<server description="payments">
  <featureManager><feature>transportSecurity-1.0</feature><feature>wmqJmsClient-2.0</feature></featureManager>
  <keyStore id="defaultKeyStore" location="key.p12" type="PKCS12" password="{aes}AB12=="/>
  <ssl id="bankSSL" keyStoreRef="defaultKeyStore" sslProtocol="TLSv1.3" clientAuthentication="true"
       enabledCiphers="TLS_AES_256_GCM_SHA384"/>
  <sslDefault sslRef="bankSSL"/>
  <httpEndpoint id="defaultHttpEndpoint" httpsPort="9443" sslRef="bankSSL"/>
</server>
""", {"X509", "TLS", "AES", "SHA-384", "TLS"})
    _c("config", "w10_java.security", """
security.provider.1=com.ibm.crypto.plus.provider.IBMJCEPlus
security.provider.2=com.ibm.crypto.provider.IBMJCE
security.provider.3=com.ibm.jsse2.IBMJSSEProvider2
security.provider.4=com.ibm.crypto.hdwrCCA.provider.IBMJCECCA
security.provider.5=sun.security.pkcs11.SunPKCS11 /etc/hsm/pkcs11.cfg
jdk.tls.disabledAlgorithms=SSLv3, TLSv1, TLSv1.1, RC4, DES, MD5withRSA, DH keySize < 1024, 3DES_EDE_CBC
jdk.tls.namedGroups=x25519, secp256r1, secp384r1, ffdhe2048
crypto.policy=unlimited
""", {"TLS", "TLS", "X25519", "ECDH", "DH"})
    _c("java", "w10_IbmJsse.java", """
import javax.net.ssl.SSLContext;
public class IbmTls {
    SSLContext ctx() throws Exception {
        System.setProperty("com.ibm.jsse2.overrideDefaultTLS", "true");
        SSLContext c = SSLContext.getInstance("SSL_TLSv2", "IBMJSSE2");
        c.init(null, null, null);
        return c;
    }
}
""", {"TLS"})
    _c("java", "w10_IbmJce.java", """
import java.security.Security;
import javax.crypto.Cipher;
public class IbmJce {
    void f() throws Exception {
        Security.insertProviderAt(new com.ibm.crypto.provider.IBMJCE(), 1);
        Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding", "IBMJCE");
    }
}
""", {"3DES"})
    # ------------------------------------------------------------- WebLogic
    _c("config", "w10_weblogic_config.xml", """
<domain>
  <server>
    <name>PaymentsServer</name>
    <ssl>
      <enabled>true</enabled>
      <hostname-verification-ignored>true</hostname-verification-ignored>
      <listen-port>7002</listen-port>
      <ciphersuite>TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384</ciphersuite>
      <minimum-tls-protocol-version>TLSv1.2</minimum-tls-protocol-version>
      <two-way-ssl-enabled>true</two-way-ssl-enabled>
    </ssl>
    <key-stores>CustomIdentityAndCustomTrust</key-stores>
    <custom-identity-key-store-type>JKS</custom-identity-key-store-type>
    <custom-identity-key-store-pass-phrase-encrypted>{AES256}Z3Vlc3M=</custom-identity-key-store-pass-phrase-encrypted>
  </server>
  <security-configuration>
    <credential-encrypted>{AES}c2VjcmV0</credential-encrypted>
    <node-manager-password-encrypted>{3DES}bGVnYWN5</node-manager-password-encrypted>
  </security-configuration>
</domain>
""", {"TLS", "X509", "AES", "3DES", "SHA-384", "ECDH", "RSA"})
    _c("config", "w10_setDomainEnv.properties", """
-Dweblogic.security.SSL.minimumProtocolVersion=TLSv1.2
-Dweblogic.security.SSL.ignoreHostnameVerification=true
-Dweblogic.security.SSL.ciphersuites=TLS_RSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
-Dweblogic.security.TrustKeyStore=CustomTrust
-Dweblogic.security.CustomTrustKeyStoreType=JKS
""", {"TLS", "TLS", "TLS", "AES", "SHA-256", "RSA", "ECDH", "ECDSA", "X509"})
    # ------------------------------------------------------- Mule / Camel / CXF
    _c("config", "w10_mule_tls.xml", """
<mule xmlns:tls="http://www.mulesoft.org/schema/mule/tls" xmlns:crypto="http://www.mulesoft.org/schema/mule/crypto">
  <tls:context name="bankTls" enabledProtocols="TLSv1.2,TLSv1.3" enabledCipherSuites="TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384">
    <tls:trust-store path="truststore.jks" password="${ts.pw}" type="jks"/>
    <tls:key-store path="keystore.p12" keyPassword="${ks.pw}" password="${ks.pw}" type="pkcs12" algorithm="RSA"/>
  </tls:context>
  <crypto:jce-config name="jce">
    <crypto:jce-key-infos><crypto:jce-symmetric-key-info keyId="k1" key="${aes.key}"/></crypto:jce-key-infos>
  </crypto:jce-config>
  <flow name="encryptPan">
    <crypto:jce-encrypt config-ref="jce" keyId="k1" algorithm="AES_GCM"/>
    <crypto:jce-sign config-ref="jce" keyId="k1" algorithm="HmacSHA256"/>
  </flow>
</mule>
""", {"TLS", "X509", "RSA", "AES", "HMAC", "SHA-256", "SHA-384", "ECDH"})
    _c("config", "w10_mule_insecure.xml", """
<tls:context name="devTls">
  <tls:trust-store insecure="true"/>
</tls:context>
<crypto:pgp-config name="pgp" publicKeyring="pub.gpg" privateKeyring="sec.gpg"/>
<secure-properties:config name="sp" file="secure.yaml" key="${enc.key}" algorithm="Blowfish"/>
""", {"TLS", "TLS", "PGP", "BLOWFISH"})
    _c("config", "w10_camel_context.xml", """
<camelContext xmlns="http://camel.apache.org/schema/spring">
  <sslContextParameters id="sslCtx" secureSocketProtocol="TLSv1.2">
    <keyManagers keyPassword="changeit"><keyStore resource="keystore.jks" type="JKS" password="changeit"/></keyManagers>
    <cipherSuitesFilter><include>TLS_ECDHE_.*_GCM_.*</include></cipherSuitesFilter>
  </sslContextParameters>
  <dataFormats>
    <crypto id="legacyDes" algorithm="DESede/CBC/PKCS5Padding" keyRef="desKey"/>
    <pgp id="pgp" keyFileName="bank.gpg" keyUserid="ops@bank" algorithm="9" hashAlgorithm="8"/>
    <secureXML id="xmlenc" secureTag="//pan" xmlCipherAlgorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>
  </dataFormats>
  <route><from uri="netty-http:https://0.0.0.0:8443/pay?sslContextParameters=#sslCtx"/><to uri="sftp://swift.bank/out?privateKeyFile=id_ed25519"/></route>
</camelContext>
""", {"TLS", "X509", "TLS", "3DES", "PGP", "AES", "SHA-256", "SSH"})
    _c("config", "w10_cxf_client.xml", """
<beans xmlns:http="http://cxf.apache.org/transports/http/configuration" xmlns:sec="http://cxf.apache.org/configuration/security">
  <http:conduit name="*.http-conduit">
    <http:tlsClientParameters secureSocketProtocol="TLSv1.2" disableCNCheck="true">
      <sec:keyManagers keyPassword="pw"><sec:keyStore type="JKS" password="pw" file="client.jks"/></sec:keyManagers>
      <sec:cipherSuitesFilter><sec:include>.*_WITH_AES_.*</sec:include><sec:exclude>.*_WITH_NULL_.*</sec:exclude></sec:cipherSuitesFilter>
    </http:tlsClientParameters>
  </http:conduit>
  <jaxws:client xmlns:jaxws="http://cxf.apache.org/jaxws">
    <jaxws:properties>
      <entry key="security.signature.properties" value="client_sign.properties"/>
      <entry key="security.asymmetric.signature.algorithm" value="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>
      <entry key="security.password.type" value="PasswordDigest"/>
    </jaxws:properties>
  </jaxws:client>
</beans>
""", {"TLS", "TLS", "X509", "TLS", "RSA", "SHA-256", "SHA-1"})
    _c("config", "w10_rampart_policy.xml", """
<wsp:Policy><sp:AsymmetricBinding><wsp:Policy>
  <sp:AlgorithmSuite><wsp:Policy><sp:Basic256Sha256Rsa15/></wsp:Policy></sp:AlgorithmSuite>
</wsp:Policy></sp:AsymmetricBinding>
<rampart:RampartConfig><rampart:encryptionUser>bank</rampart:encryptionUser><rampart:algorithmSuite>TripleDes</rampart:algorithmSuite></rampart:RampartConfig>
</wsp:Policy>
""", {"X509", "AES", "SHA-256", "3DES"})
    _c("config", "w10_wso2_carbon.xml", """
<Server>
  <Security>
    <KeyStore><Location>${carbon.home}/repository/resources/security/wso2carbon.jks</Location><Type>JKS</Type><Password>wso2carbon</Password></KeyStore>
    <InternalKeyStore><Location>internal.jks</Location><Type>JKS</Type></InternalKeyStore>
    <SymmetricEncryption><Algorithm>AES</Algorithm></SymmetricEncryption>
  </Security>
  <OAuth><IDTokenSignatureAlgorithm>SHA256withRSA</IDTokenSignatureAlgorithm></OAuth>
</Server>
""", {"X509", "AES", "RSA"})
    _c("config", "w10_jasypt_spring.xml", """
<bean id="enc" class="org.jasypt.encryption.pbe.StandardPBEStringEncryptor">
  <property name="algorithm" value="PBEWithHMACSHA512AndAES_256"/>
  <property name="password" value="${jasypt.pw}"/>
</bean>
<bean id="legacy" class="org.jasypt.util.text.BasicTextEncryptor"/>
""", {"AES", "SHA-512", "DES", "PBKDF2"})
    # ------------------------------------------------------- FIX / SWIFT
    _c("config", "w10_quickfix_initiator.cfg", """
[DEFAULT]
ConnectionType=initiator
BeginString=FIX.4.4
SenderCompID=BANK
TargetCompID=EXCHANGE
SocketUseSSL=Y
SocketKeyStore=keystore.jks
SocketKeyStoreType=JKS
EnabledProtocols=TLSv1.2
CipherSuites=TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
[SESSION]
SocketConnectHost=fix.exchange.com
SocketConnectPort=9443
""", {"TLS", "X509", "TLS", "AES", "SHA-256", "ECDH", "RSA"})
    _c("config", "w10_quickfix_plain.cfg", """
[DEFAULT]
ConnectionType=acceptor
BeginString=FIX.4.2
SenderCompID=BANK
TargetCompID=CLIENT
SocketUseSSL=N
SocketAcceptPort=5001
""", {"PLAINTEXT"})
    _c("java", "w10_QuickFixSsl.java", """
import quickfix.SessionSettings;
import quickfix.mina.ssl.SSLSupport;
public class FixSsl {
    void configure(SessionSettings s) {
        s.setBool(SSLSupport.SETTING_USE_SSL, true);
        s.setString(SSLSupport.SETTING_KEY_STORE_NAME, "bank.jks");
        s.setString(SSLSupport.SETTING_ENABLE_PROTOCOLE, "TLSv1.2");
        s.setString(SSLSupport.SETTING_CIPHER_SUITES, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");
    }
}
""", {"TLS", "AES", "SHA-384", "ECDH", "RSA"})
    _c("java", "w10_SwiftLau.java", """
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
public class SwiftLau {
    byte[] computeLAU(byte[] payload, String lauLeftKey, String lauRightKey) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec((lauLeftKey + lauRightKey).getBytes(), "HmacSHA256"));
        return mac.doFinal(payload);
    }
}
""", {"HMAC", "SHA-256"})
    _c("config", "w10_sag_lau.properties", """
swift.lau.leftKey=Abcd1234Abcd1234
swift.lau.rightKey=Abcd1234Abcd1234
swift.sag.host=sag.bank.local
""", {"HMAC", "SHA-256"})
    # ------------------------------------------------------- Thales payShield host commands in Java
    _c("java", "w10_ThalesClient.java", """
public class ThalesPayShieldClient {
    private final HsmSocket hsm;
    ThalesPayShieldClient(HsmSocket hsm) { this.hsm = hsm; }
    String generateZpk(String zmk) {
        String cmd = "A0" + "1" + "001" + "U" + zmk;
        return hsm.send("HEAD" + cmd);
    }
    String translatePin(String pinBlock, String sourceZpk, String destZpk, String pan) {
        return hsm.send("HEAD" + "CA" + sourceZpk + destZpk + "12" + pinBlock + "01" + "01" + pan);
    }
    String generateRsaKeyPair() {
        return hsm.send("HEAD" + "EI" + "2" + "2048" + "01");
    }
    String verifyArqc(String mkAc, String pan, String atc, String arqc, String data) {
        return hsm.send("HEAD" + "KQ" + "0" + "0" + mkAc + pan + atc + arqc + data);
    }
    interface HsmSocket { String send(String s); }
}
""", {"3DES", "RSA"})
    _c("java", "w10_neg_TwoLetterStrings.java", """
public class CountryCodes {
    static final String[] EU = {"AT", "BE", "CA", "DE", "EI", "ES", "FR", "KQ", "A0"};
    String state(String code) { return "CA".equals(code) ? "California" : code; }
    void command(String c) { if ("OK".equals(c)) return; }
}
""", set())
    # ------------------------------------------------------- PL/I calling ICSF
    _c("pli", "w10_pin_verify.pli", """
 PINVER: PROC OPTIONS(MAIN);
   DCL CSNBPVR ENTRY OPTIONS(ASM, INTER) EXT;
   DCL RULE_ARRAY CHAR(8) INIT('IBM-PINO');
   DCL PIN_BLOCK CHAR(8);
   /* verify the customer PIN under the PVK */
   CALL CSNBPVR(RC, RS, EXIT_LEN, EXIT_DATA, PEK_ID, PVK_ID, PROFILE,
                PAN, PIN_BLOCK, 1, RULE_ARRAY, CHK_LEN, DATA_ARRAY);
 END PINVER;
""", {"3DES"})
    _c("pli", "w10_hash.pl1", """
 HASHIT: PROC;
   DCL RULE_ARRAY(2) CHAR(8) INIT('SHA-512 ', 'ONLY    ');
   CALL CSNBOWH(RC, RS, 0, '', 2, RULE_ARRAY, TXT_LEN, TXT, CHAIN_LEN, CHAIN, HASH_LEN, HASH);
   CALL CSNBSYE(RC, RS, 0, '', 2, AES_RULES, KEY_LEN, KEY_ID, 0, '', 16, IV, 0, '', CLR_LEN, CLR, CIP_LEN, CIP, 0, '');
 END HASHIT;
""", {"SHA-512", "AES"})
    _c("pli", "w10_rsa_sign.pli", """
   DCL RULE_ARRAY CHAR(8) INIT('PKCS-1.1');
   CALL CSNDDSG(RC, RS, 0, '', 1, RULE_ARRAY, TOK_LEN, PKA_TOKEN, HASH_LEN, HASH, SIG_LEN, SIG_BITS, SIG);
""", {"RSA"})
    _c("pli", "w10_neg_records.pli", """
 CUSTUPD: PROC OPTIONS(MAIN);
   /* CALL CSNBENC was removed in 2015 - tokenised */
   DCL 1 CUST_REC,
         2 CUST_KEY CHAR(10),
         2 CUST_PASSWORD_HINT CHAR(30);
   DCL SEED FIXED BIN(31) INIT(12345);
   SAMPLE = RANDOM(SEED) * ROW_COUNT;
   READ FILE(CUSTF) INTO(CUST_REC) KEY(CUST_KEY);
 END CUSTUPD;
""", set())
    # ------------------------------------------------------- middleware negatives
    _c("config", "w10_neg_mq_queues.mqsc", """
DEFINE QLOCAL('PAYMENTS.IN') MAXDEPTH(50000) DEFPSIST(YES) REPLACE
DEFINE QLOCAL('PAYMENTS.DLQ') REPLACE
ALTER QMGR DEADQ('PAYMENTS.DLQ') MAXMSGL(4194304)
DEFINE CHANNEL('INTERNAL.SVRCONN') CHLTYPE(SVRCONN) TRPTYPE(TCP) MCAUSER('mqapp')
""", set())
    _c("config", "w10_neg_camel_routes.xml", """
<camelContext xmlns="http://camel.apache.org/schema/spring">
  <route id="settle"><from uri="file:in?noop=true"/><unmarshal><csv/></unmarshal><to uri="jms:queue:settlement"/></route>
  <route id="keys"><from uri="timer:keys"/><setHeader name="CamelFileName"><simple>${date:now:yyyyMMdd}.csv</simple></setHeader></route>
</camelContext>
""", set())
    _c("config", "w10_neg_liberty_features.xml", """
<server description="batch">
  <featureManager><feature>servlet-4.0</feature><feature>jdbc-4.2</feature><feature>batch-1.0</feature></featureManager>
  <httpEndpoint id="defaultHttpEndpoint" httpPort="9080"/>
  <dataSource jndiName="jdbc/bank"><jdbcDriver libraryRef="db2"/><properties.db2.jcc databaseName="BANK" serverName="db2" portNumber="50000"/></dataSource>
</server>
""", set())
