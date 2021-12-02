package protocol;

import javax.net.ssl.*;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.nio.channels.SocketChannel;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;

public class SecureEntity {

    public enum Mode {
        SERVER,
        CLIENT
    }
    private enum EngineOperation{
        WRAP,
        UNWRAP
    }

    private final Mode mode;
    private Socket mainSocket;
    private ArrayList<Socket> allSockets;
    private boolean hasMultipleSockets;

    private KeyStore keyStore;
    private String keyStorePassword;
    private KeyStore trustStore;

    private SSLContext sslContext;
    private SSLEngine engine;
    private ByteBuffer myAppData;
    private ByteBuffer myNetData;
    private ByteBuffer peerAppData;
    private ByteBuffer peerNetData;

    public SecureEntity(Mode mode, boolean hasMultipleSockets) {
        this.mode = mode;
        this.hasMultipleSockets = hasMultipleSockets;

        if (hasMultipleSockets){
            allSockets = new ArrayList<>();
        }
    }


    //connect without timeout
    public final void connect(String host, int port) {
        if (mode == Mode.CLIENT) {
            InetSocketAddress address = new InetSocketAddress(host, port);

            try {
                if (hasMultipleSockets){
                    Socket newSocket = new Socket();
                    newSocket.connect(address);
                    allSockets.add(newSocket);
                }else {
                    mainSocket = new Socket();
                    mainSocket.connect(address);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        else {
            try {
                throw new Exception("Entity is not a client");
            } catch (Exception e) {
                e.printStackTrace();
            }
        }//else

    }

    //connect with timeout
    public final void connect(String host, int port, int timeout) {
        if (mode == Mode.CLIENT) {
            InetSocketAddress address = new InetSocketAddress(host, port);

            try {
                if (hasMultipleSockets){
                    Socket newSocket = new Socket();
                    newSocket.connect(address, timeout);
                    allSockets.add(newSocket);
                }else {
                    mainSocket = new Socket();
                    mainSocket.connect(address, timeout);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        else {
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
                if (hasMultipleSockets){
                    Socket newSocket = listener.accept();
                    allSockets.add(newSocket);
                }else {
                    mainSocket = listener.accept();
                }

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

    public void createKeyStore(String format, String keyStoreName, String password, File directory){
        FileOutputStream out=null;
        try {
            keyStore = KeyStore.getInstance(format);
            keyStore.load(null, password.toCharArray());

            out = new FileOutputStream(directory.getAbsolutePath()+"\\"+keyStoreName+"."+format);
            keyStore.store(out, password.toCharArray());
            out.close();
        } catch (KeyStoreException  | CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

        keyStorePassword = password;
    }


    public void createTrustStore(String format, String trustStoreName, String password, File directory){
        FileOutputStream out=null;
        try {
            trustStore = KeyStore.getInstance(format);
            trustStore.load(null, null);

            out = new FileOutputStream(directory.getAbsolutePath()+"\\"+trustStoreName+"."+format);
            trustStore.store(out, password.toCharArray());
            out.close();
        } catch (KeyStoreException  | CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }

    }

    public void setupSSL() throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, KeyManagementException {
        KeyManagerFactory keyMangerFactory = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keyMangerFactory.init(keyStore, keyStorePassword.toCharArray());

        TrustManagerFactory trustManagerFactory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);

        //create SSLContext
        sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyMangerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

        //create SSLEngine
        engine = sslContext.createSSLEngine();

        //initialize buffers
        int appBufferSize = engine.getSession().getApplicationBufferSize();
        int netBufferSize = engine.getSession().getPacketBufferSize();

        myAppData   = ByteBuffer.allocate(appBufferSize);
        myNetData   = ByteBuffer.allocate(appBufferSize);
        peerAppData = ByteBuffer.allocate(appBufferSize);
        peerNetData = ByteBuffer.allocate(netBufferSize);

        if (mode == Mode.CLIENT)
            engine.setUseClientMode(true);
        else
            engine.setUseClientMode(false);

    }


    public final void doHandshake() throws SSLException {
        engine.beginHandshake();
        SSLEngineResult.HandshakeStatus handshakeStatus = engine.getHandshakeStatus();

        //process handshake message
        while (handshakeStatus != SSLEngineResult.HandshakeStatus.FINISHED && handshakeStatus != SSLEngineResult.HandshakeStatus.NOT_HANDSHAKING) {

            handshakeStatus = switch (handshakeStatus) {
                case NEED_WRAP -> operateEngine(EngineOperation.WRAP).getHandshakeStatus();
                case NEED_UNWRAP -> operateEngine(EngineOperation.UNWRAP).getHandshakeStatus();
                default -> throw new IllegalStateException("Unexpected value: " + handshakeStatus);
            };

        }//while

    }


    private SSLEngineResult operateEngine(EngineOperation operation) throws SSLException {
        SSLEngineResult operationResult;

        if (operation == EngineOperation.WRAP){
            // Empty the local network packet buffer.
            myNetData.clear();

            operationResult = engine.wrap(myAppData, myNetData);
            //TODO: manage bufferOverFlow or bufferUnderFlow statuses
            myNetData.flip();
        }

        else {
            peerNetData.flip();
            operationResult = engine.unwrap(peerNetData, peerAppData);
            peerNetData.compact();
            //TODO: manage bufferOverFlow or bufferUnderFlow statuses
        }

        return operationResult;
    }


    public Socket getSocket(){
        return mainSocket;
    }

    public KeyStore getKeyStore() {
        return keyStore;
    }

    public KeyStore getTrustStore() {
        return trustStore;
    }

}
