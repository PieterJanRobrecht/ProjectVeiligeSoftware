import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.security.cert.X509Certificate;
import java.io.*;

public class Server extends Communicator {

    private Server() {
        System.setProperty("javax.net.ssl.keyStore", "ssl/server_keystore");
        System.setProperty("javax.net.ssl.keyStorePassword", "server_keystore");
        System.setProperty("javax.net.ssl.trustStore", "ssl/server_truststore");
        System.setProperty("javax.net.ssl.trustStorePassword", "server_truststore");

        InputStream inputStream;
        OutputStream outputStream;

        SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
        SSLServerSocket sslServerSocket = null;

        try {
            sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(1337);
        } catch (IOException e) {
            System.err.println("Unable to initiate SSLServerSocket.");
        	e.printStackTrace();
            System.exit(1);
        }

        while (true) {
            try {
                SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
                sslSocket.setNeedClientAuth(false);
                SSLSession sslSession = sslSocket.getSession();
                
                //dit zorgt voor problemen :'( *sadface*
                //X509Certificate x509Certificate = sslSession.getPeerCertificateChain()[0];
                //String username = x509Certificate.getSubjectDN().getName().split("CN=")[1].split(",")[0];

                inputStream = sslSocket.getInputStream();
                outputStream = sslSocket.getOutputStream();

    			int unixTime = (int) (System.currentTimeMillis() / 1000);

                System.out.println("Client connected to fetch time, returning " + unixTime);
                
                send(""+unixTime, outputStream);
                
                inputStream.close();
                outputStream.close();

            } catch (IOException e) {
            	e.printStackTrace();
            }
        }
    }

    public static void main(String[] args) {
        new Server();
    }
}