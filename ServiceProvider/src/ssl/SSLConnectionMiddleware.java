package ssl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SSLConnectionMiddleware {
	SSLSocketFactory sslSocketFactory;
	SSLSocket sslSocket;
	
	public SSLConnectionMiddleware(){
		
        sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
        sslSocket = null;
        
//		try {
//            sslSocket = (SSLSocket) sslSocketFactory.createSocket("localhost", 13340);
//            sslSocket.startHandshake();
//
//            InputStream inputStream = sslSocket.getInputStream();
//            OutputStream outputStream = sslSocket.getOutputStream();
//
//        } catch (IOException e) {
//            System.err.println("Connection to server lost.");
//        } finally {
//            if (sslSocket != null) {
//                try {
//                    sslSocket.close();
//                } catch (IOException e) {
//                    e.printStackTrace();
//                }
//            }
//        }
	}
}
