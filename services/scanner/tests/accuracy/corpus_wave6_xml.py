"""Wave 6: XML configuration (web.config / WCF, Spring Security XML, Android
network security, Tomcat, WildFly, JDBC URLs, pom/NuGet deps, SAML/XML-DSig).
Not blind: written alongside the XML parser."""
from __future__ import annotations


def register(_c) -> None:  # noqa: C901
    _c("xml", "w6_web.config", """
<?xml version="1.0"?>
<configuration>
  <!-- <machineKey validation="MD5" /> retired 2019 -->
  <system.web>
    <machineKey validation="SHA1" decryption="3DES" validationKey="AutoGenerate,IsolateApps" />
    <httpCookies requireSSL="false" httpOnlyCookies="true" />
    <membership defaultProvider="Sql"><providers><add name="Sql" type="System.Web.Security.SqlMembershipProvider" passwordFormat="Hashed" hashAlgorithmType="SHA1" /></providers></membership>
  </system.web>
</configuration>
""", {"SHA-1", "3DES", "TLS"})
    _c("xml", "w6_app.config", """
<configuration>
  <appSettings>
    <add key="SecurityProtocol" value="Tls" />
    <add key="Jwt:Algorithm" value="HS256" />
  </appSettings>
  <connectionStrings>
    <add name="Main" connectionString="Server=db;Database=app;User Id=sa;Password=x;Encrypt=false;TrustServerCertificate=true" providerName="System.Data.SqlClient" />
  </connectionStrings>
</configuration>
""", {"TLS", "JWT"})
    _c("xml", "w6_wcf.config", """
<system.serviceModel>
  <bindings><wsHttpBinding>
    <binding name="secure"><security mode="Message"><message clientCredentialType="Certificate" algorithmSuite="Basic256Sha256Rsa15" /></security></binding>
    <binding name="open"><security mode="None" /></binding>
  </wsHttpBinding></bindings>
  <behaviors><serviceBehaviors><behavior><serviceCredentials><clientCertificate><authentication certificateValidationMode="None" /></clientCertificate></serviceCredentials></behavior></serviceBehaviors></behaviors>
</system.serviceModel>
""", {"AES", "SHA-256", "RSA", "TLS"})
    _c("xml", "w6_spring_security.xml", """
<beans:beans xmlns="http://www.springframework.org/schema/security" xmlns:beans="http://www.springframework.org/schema/beans">
  <http auto-config="true"><intercept-url pattern="/**" requires-channel="https"/></http>
  <authentication-manager><authentication-provider user-service-ref="users">
    <password-encoder hash="md5"><salt-source user-property="username"/></password-encoder>
  </authentication-provider></authentication-manager>
</beans:beans>
""", {"MD5", "TLS"})
    _c("xml", "w6_spring_beans_encoders.xml", """
<beans xmlns="http://www.springframework.org/schema/beans">
  <bean id="passwordEncoder" class="org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder"><constructor-arg value="12"/></bean>
  <bean id="legacyEncoder" class="org.springframework.security.crypto.password.NoOpPasswordEncoder" factory-method="getInstance"/>
  <bean id="encryptor" class="org.jasypt.encryption.pbe.StandardPBEStringEncryptor">
    <property name="algorithm" value="PBEWithMD5AndDES"/>
  </bean>
</beans>
""", {"BCRYPT", "PLAINTEXT", "PBKDF2", "MD5", "DES"})
    _c("xml", "w6_network_security_config.xml", """
<network-security-config>
  <base-config cleartextTrafficPermitted="true">
    <trust-anchors><certificates src="system"/><certificates src="user"/></trust-anchors>
  </base-config>
  <domain-config><domain includeSubdomains="true">api.example.com</domain>
    <pin-set expiration="2027-01-01"><pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin></pin-set>
  </domain-config>
</network-security-config>
""", {"TLS", "X509", "SHA-256"})
    _c("xml", "w6_AndroidManifest.xml", """
<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="com.example.app">
  <application android:label="@string/app_name" android:usesCleartextTraffic="true" android:networkSecurityConfig="@xml/network_security_config">
    <activity android:name=".MainActivity"/>
  </application>
</manifest>
""", {"TLS"})
    _c("xml", "w6_tomcat_server.xml", """
<Server port="8005" shutdown="SHUTDOWN"><Service name="Catalina">
  <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol" SSLEnabled="true" scheme="https" secure="true"
             sslEnabledProtocols="TLSv1,TLSv1.1,TLSv1.2" ciphers="TLS_RSA_WITH_RC4_128_SHA,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
             keystoreFile="conf/keystore.jks" keystoreType="JKS" keystorePass="changeit"/>
  <Engine name="Catalina" defaultHost="localhost">
    <Realm className="org.apache.catalina.realm.JDBCRealm" digest="MD5" connectionURL="jdbc:mysql://db/app?useSSL=false" userTable="users"/>
  </Engine>
</Service></Server>
""", {"TLS", "X509", "MD5", "RC4", "SHA-1", "RSA", "ECDH", "AES", "SHA-256"})
    _c("xml", "w6_wildfly_standalone.xml", """
<subsystem xmlns="urn:wildfly:elytron:15.0">
  <tls><key-stores><key-store name="app"><credential-reference clear-text="secret"/><implementation type="JKS"/><file path="app.jks"/></key-store></key-stores>
    <server-ssl-contexts><server-ssl-context name="app" protocols="TLSv1.2 TLSv1.3" key-manager="km" cipher-suite-filter="DEFAULT"/></server-ssl-contexts>
  </tls>
  <mappers><simple-digest-mapper name="d" algorithm="simple-digest-sha-512"/><bcrypt-mapper name="b"/></mappers>
</subsystem>
""", {"TLS", "SHA-512", "BCRYPT"})
    _c("xml", "w6_persistence.xml", """
<persistence xmlns="http://java.sun.com/xml/ns/persistence" version="2.0">
  <persistence-unit name="app">
    <properties>
      <property name="javax.persistence.jdbc.url" value="jdbc:postgresql://db:5432/app?sslmode=disable"/>
      <property name="hibernate.dialect" value="org.hibernate.dialect.PostgreSQLDialect"/>
    </properties>
  </persistence-unit>
</persistence>
""", {"TLS"})
    _c("xml", "w6_pom.xml", """
<project><modelVersion>4.0.0</modelVersion>
  <dependencies>
    <dependency><groupId>io.jsonwebtoken</groupId><artifactId>jjwt-api</artifactId><version>0.12.5</version></dependency>
    <dependency><groupId>at.favre.lib</groupId><artifactId>bcrypt</artifactId><version>0.10.2</version></dependency>
    <dependency><groupId>com.fasterxml.jackson.core</groupId><artifactId>jackson-databind</artifactId></dependency>
  </dependencies>
</project>
""", {"JWT", "BCRYPT"})
    _c("xml", "w6_app.csproj", """
<Project Sdk="Microsoft.NET.Sdk.Web">
  <ItemGroup>
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="8.0.0" />
    <PackageReference Include="BCrypt.Net-Next" Version="4.0.3" />
    <PackageReference Include="Newtonsoft.Json" Version="13.0.3" />
  </ItemGroup>
</Project>
""", {"JWT", "BCRYPT"})
    _c("xml", "w6_saml_metadata.xml", """
<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.com">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo>
    <ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>
    <ds:Reference><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/></ds:Reference>
  </ds:SignedInfo><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIC...</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>
</md:EntityDescriptor>
""", {"RSA", "SHA-1", "SHA-256", "X509"})
    _c("xml", "w6_xmlenc.xml", """
<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#">
  <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/>
  <ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"/></xenc:EncryptedKey></ds:KeyInfo>
</xenc:EncryptedData>
""", {"AES", "RSA"})
    _c("xml", "w6_app_settings_values.xml", """
<settings>
  <security>
    <hashAlgorithm>SHA-512</hashAlgorithm>
    <cipher>AES/GCM/NoPadding</cipher>
    <minTlsVersion>TLSv1.2</minTlsVersion>
    <jwtAlgorithm>RS256</jwtAlgorithm>
  </security>
</settings>
""", {"SHA-512", "AES", "TLS", "JWT"})
    # ------------------------------------------------------------ negatives
    _c("xml", "w6_neg_layout.xml", """
<LinearLayout xmlns:android="http://schemas.android.com/apk/res/android" android:orientation="vertical">
  <TextView android:id="@+id/description" android:text="The shader uses md5sum-like hashing for cache keys"/>
  <Button android:id="@+id/aes_button" android:text="AES (Automated Export System) filing"/>
</LinearLayout>
""", set(), "negative")
    _c("xml", "w6_neg_pom_plain.xml", """
<project><dependencies>
  <dependency><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-web</artifactId></dependency>
  <dependency><groupId>org.projectlombok</groupId><artifactId>lombok</artifactId><scope>provided</scope></dependency>
</dependencies></project>
""", set(), "negative")
    _c("xml", "w6_neg_comments_only.xml", """
<configuration>
  <!-- machineKey validation="MD5" decryption="DES" — removed, see ticket SEC-42 -->
  <!-- <add key="SecurityProtocol" value="Ssl3" /> -->
  <appSettings><add key="Theme" value="dark" /></appSettings>
</configuration>
""", set(), "negative")
    _c("xml", "w6_neg_svg.xml", """
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24"><path d="M12 2a10 10 0 100 20 10 10 0 000-20z" fill="#3DES1A"/><desc>tls-lock-icon</desc></svg>
""", set(), "negative")
    _c("xml", "w6_neg_jdbc_plain.xml", """
<bean id="dataSource" class="com.zaxxer.hikari.HikariDataSource">
  <property name="jdbcUrl" value="jdbc:h2:mem:testdb;DB_CLOSE_DELAY=-1"/>
  <property name="username" value="sa"/>
</bean>
""", set(), "negative")
