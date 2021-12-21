package wak.ssl;

import javax.net.ssl.*;
import java.io.*;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.HashMap;

public class SSLManager {

    public enum Mode {
        SERVER,
        CLIENT
    }

    private final Mode mode;

    private KeyStore keyStore;
    private FileOutputStream keyOut;
    private String keyStorePassword = "";
    private KeyStore trustStore;
    private FileOutputStream trustOut;

    private SSLContext sslContext;
    private SSLEngine engine;
    private ByteBuffer localData;     //plaintext local data
    private ByteBuffer peerData;      //plaintext peer data
    private ByteBuffer networkData;   //encrypted data


    public SSLManager(Mode mode) {
        this.mode = mode;
    }

    public void loadKeyStore(String format, String password, File filePath){
        keyOut = null;
        try {
            FileInputStream fis = new FileInputStream(filePath);
            keyStore = KeyStore.getInstance(format);
            keyStore.load(fis, password.toCharArray());

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        keyStorePassword = password;

    }


    public void createKeyStore(String format, String keyStoreName, String password, File directory) {

        try {
            keyStore = KeyStore.getInstance(format);
            keyStore.load(null, password.toCharArray());

            keyOut = new FileOutputStream(directory.getAbsolutePath() + "\\" + keyStoreName + "." + format);
            keyStore.store(keyOut, password.toCharArray());
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        keyStorePassword = password;

    }



    public void loadTrustStore(String format, File filePath){

        try {
            FileInputStream fis = new FileInputStream(filePath);
            trustStore = KeyStore.getInstance(format);
            trustStore.load(fis, "".toCharArray());

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }


    }



    public void createTrustStore(String format, String trustStoreName, String password, File directory) {
        trustOut = null;
        try {
            trustStore = KeyStore.getInstance(format);
            trustStore.load(null, password.toCharArray());

            trustOut = new FileOutputStream(directory.getAbsolutePath() + "\\" + trustStoreName + "." + format);
            trustStore.store(trustOut, password.toCharArray());


        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }


    }

    public void setupSSL(String protocol) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        KeyManagerFactory keyMangerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyMangerFactory.init(keyStore, keyStorePassword.toCharArray());


        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);

        //create SSLContext
        sslContext = SSLContext.getInstance(protocol);
        sslContext.init(keyMangerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

        //create SSLEngine
        engine = sslContext.createSSLEngine();

        if (mode == Mode.CLIENT) {
            engine.setUseClientMode(true);
        } else {
            engine.setUseClientMode(false);
            engine.setNeedClientAuth(false);
        }

        //initialize buffers
        int appBufferSize = engine.getSession().getApplicationBufferSize();
        int netBufferSize = engine.getSession().getPacketBufferSize();

        peerData = ByteBuffer.allocate(appBufferSize);
        localData = ByteBuffer.allocate(appBufferSize);
        networkData = ByteBuffer.allocate(netBufferSize);

    }


    public boolean doHandshake(Object connectionBridge) {
        boolean successfulHandshake = false;

        try {
            engine.beginHandshake();
            SSLEngineResult.HandshakeStatus handshakeStatus = engine.getHandshakeStatus();

            while (handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED && handshakeStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {

                SSLEngineResult result = null;
                if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP) {

                    //encrypt data and store in networkData buffer
                    localData.flip();
                    result = engine.wrap(localData, networkData);
                    localData.compact();

                    //send encrypted data to peer
                    networkData.flip();
                    while (networkData.hasRemaining()) {
                        if (connectionBridge instanceof Socket) {
                            ((Socket) connectionBridge).getOutputStream().write(networkData.get());
                            ((Socket) connectionBridge).getOutputStream().flush();
                        } else if (connectionBridge instanceof SocketChannel) {
                            ((SocketChannel) connectionBridge).write(networkData);
                        }
                    }//while

                    //enable write mode
                    networkData.compact();


                } else if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP) {

                    //read next handshake message
                    do {
                        byte holder;
                        if (connectionBridge instanceof Socket) {
                            holder = (byte) ((Socket) connectionBridge).getInputStream().read();
                            networkData.put(holder);
                        } else if (connectionBridge instanceof SocketChannel) {
                            ((SocketChannel) connectionBridge).read(networkData);
                        }

                        networkData.flip();
                        result = engine.unwrap(networkData, peerData);  //decrypt data and store in peerData buffer
                        networkData.compact();

                    } while (result.getStatus() == SSLEngineResult.Status.BUFFER_UNDERFLOW);

                }//else


                successfulHandshake = (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED);
                runDelegatedTasks();
                handshakeStatus = engine.getHandshakeStatus();

            }//while


        } catch (SSLException e) {
            e.printStackTrace();

        } catch (IOException e) {
            e.printStackTrace();

        }


        return successfulHandshake;
    }


    private SSLEngineResult.HandshakeStatus runDelegatedTasks() throws SSLException {

        while (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            Runnable runnable = engine.getDelegatedTask();
            if (runnable == null) {
                break;
            } else {
                runnable.run();

            }
        }

        return engine.getHandshakeStatus();

    }

    public void addTrustedCertificates(HashMap<String, Certificate> trustedCertificates) {

        for (String alias : trustedCertificates.keySet()) {
            Certificate certificate = trustedCertificates.get(alias);
            try {
                trustStore.setCertificateEntry(alias, certificate);
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        }

        try {
            trustStore.store(trustOut, "".toCharArray());
            trustOut.close();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }
    }


    public void addLocalCertificates(HashMap<String, LocalCertificate> localCertificates) {

        for (String name : localCertificates.keySet()) {
            LocalCertificate localCertificate = localCertificates.get(name);
            try {
                keyStore.setKeyEntry(name, localCertificate.getPrivateKey(), localCertificate.getPassword(), localCertificate.getChain());
            } catch (KeyStoreException e) {
                e.printStackTrace();
            }
        }

        try {
            keyStore.store(keyOut, keyStorePassword.toCharArray());
            keyOut.close();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (CertificateException e) {
            e.printStackTrace();
        }

    }


    //for application data
    public byte[] encrypt(byte[] unencryptedData) throws SSLException {

        localData.put(unencryptedData);

        //encrypt data and store in networkData buffer
        localData.flip();
        engine.wrap(localData, networkData);
        localData.compact();

        networkData.flip();
        byte[] encrypted = new byte[networkData.limit()];
        networkData.get(encrypted);
        networkData.compact();

        return encrypted;
    }


    //for application data
    public byte[] decrypt(byte[] encryptedData) throws SSLException {

        networkData.put(encryptedData);

        //decrypt encrypted peer application data and store in peerData buffer
        networkData.flip();
        engine.unwrap(networkData, peerData);
        networkData.compact();

        peerData.flip();
        byte[] decrypted = new byte[peerData.limit()];
        peerData.get(decrypted);
        peerData.compact();

        return decrypted;
    }


}
