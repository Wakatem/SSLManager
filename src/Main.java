import org.bouncycastle.asn1.*;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.mime.encoding.Base64InputStream;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Base64Encoder;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;
import protocol.*;

import javax.crypto.EncryptedPrivateKeyInfo;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.*;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.*;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Scanner;
import java.util.Set;

public class Main {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, KeyManagementException, UnrecoverableKeyException {

        showConsole();


        CertificateGenerator generator = new CertificateGenerator();


/*
        //create CA certificate
        SecureRandom CA_random = new SecureRandom();
        KeyPair CA_keyPair = generator.generateKeyPair("RSA", 2048, CA_random);
        X509Certificate CA_Certificate1 = generator.generateSelfSignedCert("SHA256WithRSA", CA_random, CA_keyPair, "localhost", 365);

        FileOutputStream fos = new FileOutputStream("CA.crt");
        fos.write(CA_Certificate1.getEncoded());
        fos.close();



        fos = new FileOutputStream("privatekey.key");
        fos.write(CA_keyPair.getPrivate().getEncoded());
        fos.close();


        SecureRandom random = new SecureRandom();
        KeyPair subjectKeyPair = generator.generateKeyPair("RSA", 2048, random);
        X509Certificate serverCert = generator.generateCertificate("SHA256WithRSA", random, subjectKeyPair, "localhost", "DubaiEXPO", CA_keyPair.getPrivate(), 365);

        fos = new FileOutputStream("server.crt");
        fos.write(serverCert.getEncoded());
        fos.close();



 */

        CertificateFactory CAfactory = CertificateFactory.getInstance("X509");
        FileInputStream fis = new FileInputStream("CA.crt");
        X509Certificate CA_Certificate = (X509Certificate) CAfactory.generateCertificate(fis);

        FileInputStream fis2 = new FileInputStream("privatekey.key");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(fis2.readAllBytes());
        KeyFactory factory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = null;
        try {
            privateKey = factory.generatePrivate(keySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
        }


        Scanner scanner = new Scanner(System.in);
        int input = scanner.nextInt();
        if (input == 0) {


            //create & initialize SecureEntity object
            SecureEntity secureEntity = new SecureEntity(SecureEntity.Mode.SERVER);

            //create keystore and truststore
            File directory = new File(System.getProperty("user.home") + "\\DubaiEXPO\\Secure");
            if (!directory.exists())
                directory.mkdirs();

            FileOutputStream keystoreOut = secureEntity.createKeyStore("jks", "serverSTORE", "123", directory);
            FileOutputStream truststoreOut = secureEntity.createTrustStore("jks", "serverTRUST", "123", directory);


            //load certificates (create first if necessary)
            SecureRandom random = new SecureRandom();
            KeyPair subjectKeyPair = generator.generateKeyPair("RSA", 2048, random);
            //X509Certificate serverCert = generator.generateSignedCertificate("SHA256WithRSA", random, subjectKeyPair, "localhost", "DubaiEXPO", null, 365);

            //secureEntity.getKeyStore().setCertificateEntry("localserver", CA_Certificate);
            secureEntity.getKeyStore().setKeyEntry("localserver", privateKey, "123".toCharArray(), new Certificate[]{CA_Certificate});
            secureEntity.getKeyStore().store(keystoreOut, "123".toCharArray());

            keystoreOut.close();
            truststoreOut.close();

            //connect (or listen)
            secureEntity.listen(34690);

            //setup SSL
            secureEntity.setupSSL();

            //SSL Handshake
            if (secureEntity.doHandshake() == false) {
                System.out.println("-- handshake not completed\n-- Ending program");
                secureEntity.getMainSocket().close();
                secureEntity.getInputPipe().close();
                secureEntity.getOutputPipe().close();
                System.exit(1);
            }

            System.out.println("DONE");

            //communicate

            new Thread(new Runnable() {
                @Override
                public void run() {
                    try {
                        while (secureEntity.getMainSocket().isConnected()) {
                            //System.out.println(secureEntity.getInputPipe().readUTF());
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    } finally {
                        try {
                            secureEntity.getInputPipe().close();
                            secureEntity.getOutputPipe().close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }


                }
            }).start();


        } else {

            //create & initialize SecureEntity object
            SecureEntity secureEntity = new SecureEntity(SecureEntity.Mode.CLIENT);

            //create keystore and truststore
            File directory = new File(System.getProperty("user.home") + "\\DubaiEXPO\\Secure");
            if (!directory.exists())
                directory.mkdirs();

            FileOutputStream truststoreOut = secureEntity.createTrustStore("jks", "clientTRUST", "helloWorld", directory);

            //load certificates (create first if necessary)
            secureEntity.getTrustStore().setCertificateEntry("CA", CA_Certificate);
            secureEntity.getTrustStore().store(truststoreOut, "helloWorld".toCharArray());

            truststoreOut.close();


            //connect (or listen)
            secureEntity.connect("localhost", 34690);

            //setup SSL
            secureEntity.setupSSL();

            //SSL Handshake
            if (secureEntity.doHandshake() == false) {
                System.out.println("-- handshake not completed\n-- Ending program");
                secureEntity.getMainSocket().close();
                secureEntity.getInputPipe().close();
                secureEntity.getOutputPipe().close();
                System.exit(1);
            }

            System.out.println("DONE");

            //communicate
            new Thread(new Runnable() {
                @Override
                public void run() {
                    Scanner scanner = new Scanner(System.in);
                    String message;
                    try {
                        while (secureEntity.getMainSocket().isConnected()) {
                            message = scanner.nextLine();
                            secureEntity.getOutputPipe().write(2);
                        }

                    } catch (IOException e) {
                        e.printStackTrace();
                    } finally {
                        try {
                            secureEntity.getInputPipe().close();
                            secureEntity.getOutputPipe().close();
                        } catch (IOException e) {
                            e.printStackTrace();
                        }
                    }
                }
            }).start();
        }

    }


    public static void showConsole() {
        //if current process has no window
        if (System.console() == null) {
            try {
                Runtime.getRuntime().exec("cmd /c start java -jar sharedProtocolAssignment.jar");
            } catch (IOException e) {
                e.printStackTrace();
            }

            return; //System.exit();   or   return;
        }
    }


    public static void certificateValidtor(Certificate certificate, KeyStore trustStore) {
        try {
            Certificate[] ex = new Certificate[]{certificate};
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            CertificateFactory factory = CertificateFactory.getInstance("X509");
            CertPath certPath = factory.generateCertPath(Arrays.asList(ex));
            PKIXParameters params = new PKIXParameters(trustStore);
            params.setRevocationEnabled(false);
            validator.validate(certPath, params);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
