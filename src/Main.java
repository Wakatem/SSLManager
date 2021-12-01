import protocol.*;

import java.io.File;
import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class Main {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, KeyManagementException, UnrecoverableKeyException {


        //TODO: create CA certificate
        Certificate CA_Certificate = createCACertificate();


        //create & initialize SecureEntity object
        SecureEntity secureEntity = new SecureEntity(SecureEntity.Mode.SERVER, false);

        //create keystore and truststore
        File directory = new File(System.getProperty("user.home")+"\\DubaiEXPO\\Secure");
        if (!directory.exists())
            directory.mkdirs();

        secureEntity.createKeyStore("jks", "STORE", "123", directory);
        secureEntity.createTrustStore("jks", "TRUST", directory);

        //load certificates (create first if necessary)

        //setup SSL
        secureEntity.setupSSL();

        //connect (or listen)

        //initiate SSL Handshake

        //communicate


    }



    public static Certificate createCACertificate(){
        CertificateGenerator generator = new CertificateGenerator();
        SecureRandom random = new SecureRandom();

        generator.generateKeyPair("RSA", 2048, random);
        return generator.generateCertificate("SHA256withRSA", random, "DubaiEXPO", 365);

    }



}
