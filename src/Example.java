import wak.ssl.LocalCertificate;
import wak.ssl.SSLManager;

import javax.net.ssl.SSLException;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.*;
import java.util.*;

public class Example {

    public static void main(String[] args) throws IOException, NoSuchAlgorithmException, KeyStoreException, CertificateException, KeyManagementException, UnrecoverableKeyException {

        //load certificate
        CertificateFactory CAfactory = CertificateFactory.getInstance("X509");
        FileInputStream fis = new FileInputStream("CA.crt");
        X509Certificate CA_Certificate = (X509Certificate) CAfactory.generateCertificate(fis);


        Scanner scanner = new Scanner(System.in);
        int input = scanner.nextInt();


        if (input == 0) {

            FileInputStream fis2 = new FileInputStream("privatekey.key");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(fis2.readAllBytes());
            KeyFactory factory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = null;
            try {
                privateKey = factory.generatePrivate(keySpec);
            } catch (InvalidKeySpecException e) {
                e.printStackTrace();
            }

            ServerSocket listener = new ServerSocket(443);
            Socket server = listener.accept();

            SSLManager manager = new SSLManager(SSLManager.Mode.SERVER);

            //create/load keystore and truststore
            File directory = new File(System.getProperty("user.home") + "\\DubaiEXPO\\Secure");
            if (!directory.exists())
                directory.mkdirs();


            //load certificates (create first if necessary)
            manager.createTrustStore("jks", "clientTRUST", "", directory);
            HashMap<String, Certificate> trustedCA = new HashMap<>();
            trustedCA.put("CA", CA_Certificate);
            manager.addTrustedCertificates(trustedCA);

            manager.createKeyStore("jks", "serverSTORE", "123", directory);
            HashMap<String, LocalCertificate> localCertificates = new HashMap<>();
            localCertificates.put("localserver", new LocalCertificate( privateKey, "123", new Certificate[]{CA_Certificate}));
            manager.addLocalCertificates(localCertificates);


            //setup SSL
            manager.setupSSL("TLSv1.2");

            //SSL Handshake
            if (manager.doHandshake(server) == false) {
                System.out.println("-- handshake not completed\n-- Ending program");
                System.exit(1);
            }

            System.out.println("SSL Handshake is successful");


            //exchange application data
            ByteArrayOutputStream stream = new ByteArrayOutputStream();
            BufferedInputStream stream1=null;
            try {
                stream1 = new BufferedInputStream(server.getInputStream());
            } catch (IOException e) {
                e.printStackTrace();
            }
            boolean bytesReady = false;
            while (server.isConnected()) {
                try {


                    while (stream1.available() > 0){
                        stream.write(stream1.read());
                        bytesReady = true;

                    }

                    if (bytesReady) {
                        String string = new String(manager.decrypt(stream.toByteArray()));
                        System.out.println(string);
                        stream.reset();
                        bytesReady = false;
                    }

                } catch (SSLException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }



        } else {
            Socket client = new Socket("localhost", 443);

            SSLManager manager = new SSLManager(SSLManager.Mode.CLIENT);

            //create or load keystore and truststore
            File directory = new File(System.getProperty("user.home") + "\\DubaiEXPO\\Secure");
            if (!directory.exists())
                directory.mkdirs();


            manager.createTrustStore("jks", "clientTRUST", "", directory);

            HashMap<String, Certificate> trustedCA = new HashMap<>();
            trustedCA.put("CA", CA_Certificate);
            manager.addTrustedCertificates(trustedCA);


            //setup SSL
            manager.setupSSL("TLSv1.2");

            //SSL Handshake
            if (manager.doHandshake(client) == false) {
                System.out.println("-- handshake not completed\n-- Ending program");
                System.exit(1);
            }

            System.out.println("SSL Handshake is successful");


            //exchange application data
            while (client.isConnected()) {
                String message = scanner.nextLine();
                try {
                    byte[] data = manager.encrypt(message.getBytes());
                    client.getOutputStream().write(data);
                    client.getOutputStream().flush();
                } catch (SSLException e) {
                    e.printStackTrace();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }



        }
    }


}
