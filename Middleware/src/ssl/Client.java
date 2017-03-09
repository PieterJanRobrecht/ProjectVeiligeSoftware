//package ssl;
//
////DO NOT USE
//
//import javax.net.ssl.SSLSocket;
//import javax.net.ssl.SSLSocketFactory;
//import java.io.IOException;
//import java.io.InputStream;
//import java.io.OutputStream;
//
//public class Client extends Communicator {
//    public Client() {
//
//        //System.setProperty("javax.net.ssl.keyStore", "ssl/Obama");
//        //System.setProperty("javax.net.ssl.keyStorePassword", "ThankYou");
//        System.setProperty("javax.net.ssl.trustStore", "ssl/client_truststore");
//        System.setProperty("javax.net.ssl.trustStorePassword", "client_truststore");
//
//        SSLSocketFactory sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
//        SSLSocket sslSocket = null;
//        
//        try {
//            sslSocket = (SSLSocket) sslSocketFactory.createSocket("localhost", 1337);
//            sslSocket.startHandshake();
//
//            InputStream inputStream = sslSocket.getInputStream();
//            OutputStream outputStream = sslSocket.getOutputStream();
//
//            System.out.println(receive(inputStream));
//            
//            inputStream.close();
//            outputStream.close();
//            
//        } catch (IOException e) {
//        	System.err.println(e.toString());
//        } finally {
//            if (sslSocket != null) {
//                try {
//                    sslSocket.close();
//                } catch (IOException e) {
//                    e.printStackTrace();
//                }
//            }
//        }
//    }
//
//    public static void main(String[] args) {
//        new Client();
//    }
//}