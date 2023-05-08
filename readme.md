# SSLManager 
![image](https://img.shields.io/badge/Project%20State-Active-brightgreen)

`SSLManager` is an implementation of SSLEngine that aims to provide a simple, yet flexible interface to establish SSL/TLS connections with blocking and non-blocking modes. `SSLManager` handles loading and creating keystore and truststore, as well as adding relevant entries to them. To ensure consistent handshake process, `SSLManager` enters blocking mode when it is in handshake mode, and remains transport-independent after a successful handshake.

The library comes with an additional class. `LocalCertificate` is used to encapsulate the details needed to add a server/client certificate in a keystore.

**SSLManager traits:**
- Transport-Independent
- Handles SSL handshake automatically
- Encapsulates initial SSL/TLS setup steps
- Ensures exchanged application data is not lost

## How It Works

After establishing connection with the peer, an object of `SSLManager` is instantiated, specifying its role in the connection.
```java 
SSLManager manager = new SSLManager(SSLManager.Mode.CLIENT);
```

<br/>

Keystores and Truststores are created or loaded from files accordingly based on the preferred SSL connection requirements.
```java
manager.createTrustStore("jks", "clientTRUST", "", directory);
```

<br/>

`addTrustedCertificates` and `addLocalCertificates` methods accept a hashmap. A single entry consists of a key that corresponds to the alias the certificate is going to be added as, and a value of type `Certificate` or `LocalCertificate` that corresponds to the certificate/certificate chain being added.
```java
manager.createTrustStore("jks", "clientTRUST", "", directory);
HashMap<String, Certificate> trustedCA = new HashMap<>();
trustedCA.put("CA", CA_Certificate);
manager.addTrustedCertificates(trustedCA);
```


<br/>

Create `SSLContext` from provided fields and explicity-defined protocol
```java
manager.setupSSL("TLSv1.2");
```


<br/>

Begin SSLHandshake (*client* is of type `Socket` or `SocketChannel`)
```java
manager.doHandshake(client);
```

<br/>

After a successful handshake, `SSLManager` can now be used to encrypt and decrypt application data. `encrypt` method accepts unencrypted array of bytes and returns an encrypted array of bytes. Vice versa applies for `decrypt` method.
```java
byte[] encryptedData = manager.encrypt(message.getBytes());
byte[] decryptedData = manager.decrypt(stream.toByteArray());
```

<br/>

## More Info 

The current version of the library supports one-way SSL and provides the basics. More features will be implemented with time. The project is built with OpenJDK 17.0.1 on Intellij IDEA and provides an example demonstrating the use of the library. To run the example, a server certificate and private key, and a trusted certificate for the client side must be provided. An exported jar file of the library is also available in
[Releases](https://github.com/Wakatem/SSLManager/releases/tag/v1.0.0).

<br/>

## Links 

- [JSSE Documentation](https://docs.oracle.com/javase/8/docs/technotes/guides/security/jsse/JSSERefGuide.html)  

