package protocol;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import javax.net.ssl.*;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Properties;
import java.util.Scanner;

public class SecureEntity {

    public enum Mode {
        SERVER,
        CLIENT
    }

    private enum EngineOperation {
        WRAP,
        UNWRAP,
        TASK
    }

    private final Mode mode;
    private Socket mainSocket;
    private DataInputStream inputPipe;
    private DataOutputStream outputPipe;

    private KeyStore keyStore;
    private String keyStorePassword = "";
    private KeyStore trustStore;

    private boolean successfulHandshake;
    private SSLContext sslContext;
    private SSLEngine engine;
    private ByteBuffer localData;     //plaintext local data
    private ByteBuffer peerData;      //plaintext peer data
    private ByteBuffer networkData;   //encrypted data

    public SecureEntity(Mode mode) {
        this.mode = mode;
    }


    //connect without timeout
    public final void connect(String host, int port) {
        if (mode == Mode.CLIENT) {
            InetSocketAddress address = new InetSocketAddress(host, port);

            try {
                mainSocket = new Socket();
                mainSocket.connect(address);
                inputPipe = new DataInputStream(mainSocket.getInputStream());
                outputPipe = new DataOutputStream(mainSocket.getOutputStream());
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            try {
                throw new Exception("Entity is not a client");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }//else

    }


    public final void listen(int port) {
        if (mode == Mode.SERVER) {
            ServerSocket listener;
            try {
                listener = new ServerSocket(port);
                mainSocket = listener.accept();
                inputPipe = new DataInputStream(new DataInputStream(mainSocket.getInputStream()));
                outputPipe = new DataOutputStream(new DataOutputStream(mainSocket.getOutputStream()));
            } catch (IOException e) {
                e.printStackTrace();
            }

        } else {
            try {
                throw new Exception("Entity is not a server");
            } catch (Exception e) {
                e.printStackTrace();
            }

        }//else

    }


    public FileOutputStream createKeyStore(String format, String keyStoreName, String password, File directory) {
        FileOutputStream out = null;
        try {
            keyStore = KeyStore.getInstance(format);
            keyStore.load(null, password.toCharArray());

            out = new FileOutputStream(directory.getAbsolutePath() + "\\" + keyStoreName + "." + format);
            keyStore.store(out, password.toCharArray());
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        keyStorePassword = password;
        return out;
    }


    public FileOutputStream createTrustStore(String format, String trustStoreName, String password, File directory) {
        FileOutputStream out = null;
        try {
            trustStore = KeyStore.getInstance(format);
            trustStore.load(null, password.toCharArray());

            out = new FileOutputStream(directory.getAbsolutePath() + "\\" + trustStoreName + "." + format);
            trustStore.store(out, password.toCharArray());


        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return out;
    }

    public void setupSSL() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        KeyManagerFactory keyMangerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyMangerFactory.init(keyStore, keyStorePassword.toCharArray());


        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);

        //create SSLContext
        sslContext = SSLContext.getInstance("TLSv1.2");
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


    public boolean doHandshake() {

        try {
            engine.beginHandshake();
            SSLEngineResult.HandshakeStatus handshakeStatus = engine.getHandshakeStatus();

            while (handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED && handshakeStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {

                if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_WRAP){
                    operateSSLEngine(true, EngineOperation.WRAP);
                    runDelegatedTasks();
                    handshakeStatus = engine.getHandshakeStatus();

                }else if (handshakeStatus == SSLEngineResult.HandshakeStatus.NEED_UNWRAP){
                    operateSSLEngine(true, EngineOperation.UNWRAP);
                    runDelegatedTasks();
                    handshakeStatus = engine.getHandshakeStatus();
                }


            }//while


        } catch (SSLException e) {
            e.printStackTrace();

        } catch (IOException e) {
            e.printStackTrace();

        }


        return successfulHandshake;
    }

    public SSLEngineResult operateSSLEngine(boolean inHandshakeStage, EngineOperation operation) throws IOException {

        SSLEngineResult result;

        if (operation == EngineOperation.WRAP) {
            localData.flip();

            //encrypt data and store in networkData buffer
            result = engine.wrap(localData, networkData);
            if (inHandshakeStage)
                successfulHandshake = (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED);
            localData.compact();


            //send data to peer
            networkData.flip();
            outputPipe.writeUTF("b:" + String.valueOf(networkData.limit())); //size of sent message
            while (networkData.hasRemaining()) {
                outputPipe.write(networkData.get());
                outputPipe.flush();
            }//while


        } else {

            //read next handshake message
            int expectedSize = Integer.parseInt(inputPipe.readUTF().substring(2));
            int readBytesCounter = 0;
            while (readBytesCounter != expectedSize) {
                networkData.put((byte) inputPipe.read());
                readBytesCounter++;
            }


            //decrypt data and store in peerData buffer
            networkData.flip();
            result = engine.unwrap(networkData, peerData);
            if (inHandshakeStage)
                successfulHandshake = (result.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.FINISHED);

        }


        //enable write mode
        networkData.compact();
        //empty network buffer
        networkData.clear();

        return result;
    }


    public SSLEngineResult.HandshakeStatus runDelegatedTasks() throws SSLException {

        while (engine.getHandshakeStatus() == SSLEngineResult.HandshakeStatus.NEED_TASK) {
            Runnable runnable = engine.getDelegatedTask();
            if (runnable == null) {
                break;
            } else {
                //System.out.println("task needed");
                runnable.run();
                //System.out.println("Handshake after task: " + engine.getHandshakeStatus());

            }
        }

        return engine.getHandshakeStatus();

    }


    public Socket getMainSocket() {
        return mainSocket;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public KeyStore getTrustStore() {
        return trustStore;
    }

    public DataOutputStream getOutputPipe() {
        return outputPipe;
    }

    public DataInputStream getInputPipe() {
        return inputPipe;
    }


    private byte[] readBytes() {
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();


        try {
            byte holder = 'o';
            while ((holder = (byte) inputPipe.read()) != '@') {
                outputStream.write(holder);
            }

        } catch (IOException e) {
            e.printStackTrace();
        }


        return outputStream.toByteArray();
    }
}


