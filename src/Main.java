import protocol.*;
import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class Main {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, KeyManagementException, UnrecoverableKeyException {

        CertificateGenerator generator = new CertificateGenerator();

        //TODO: create CA certificate
        SecureRandom CA_random = new SecureRandom();
        KeyPair CA_keyPair = generator.generateKeyPair("RSA", 2048, CA_random);
        Certificate CA_Certificate = generator.generateCertificate("SHA256withRSA", CA_random, CA_keyPair, "DubaiEXPO", 365);



        //create & initialize SecureEntity object
        SecureEntity secureEntity = new SecureEntity(SecureEntity.Mode.SERVER, false);

        //create keystore and truststore
        File directory = new File(System.getProperty("user.home")+"\\DubaiEXPO\\Secure");
        if (!directory.exists())
            directory.mkdirs();

        secureEntity.createKeyStore("jks", "STORE", "123", directory);
        secureEntity.createTrustStore("jks", "TRUST", "123", directory);


        //load certificates (create first if necessary)
        SecureRandom random = new SecureRandom();
        KeyPair subjectKeyPair = generator.generateKeyPair("RSA", 2048, random);
        Certificate randomCertificate = generator.generateCertificate("SHA256WithRSA", random, subjectKeyPair, "server", "DubaiEXPO", CA_keyPair.getPrivate(), 365);

        secureEntity.getKeyStore().setKeyEntry("randomCertificate", subjectKeyPair.getPrivate(), "123".toCharArray(), new Certificate[]{randomCertificate});
        secureEntity.getTrustStore().setCertificateEntry("DubaiEXPO", CA_Certificate);


        //setup SSL
         //secureEntity.setupSSL();

        //connect (or listen)

        //initiate SSL Handshake

        //communicate


    }



}
