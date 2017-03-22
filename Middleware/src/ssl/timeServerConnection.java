package ssl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class timeServerConnection extends Communicator {
	SSLSocketFactory sslSocketFactory;
	SSLSocket sslSocket;
	InputStream inputStream;
	OutputStream outputStream;

	public timeServerConnection() {
		System.setProperty("javax.net.ssl.trustStore", "ssl/client_truststore");
		System.setProperty("javax.net.ssl.trustStorePassword", "client_truststore");

		sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		sslSocket = null;
	}

	public int getTime() {
		int time = -1;
		try {
			sslSocket = (SSLSocket) sslSocketFactory.createSocket("localhost", 1337);
			sslSocket.startHandshake();

			InputStream inputStream = sslSocket.getInputStream();
			OutputStream outputStream = sslSocket.getOutputStream();

			time = Integer.parseInt(receive(inputStream));

			inputStream.close();
			outputStream.close();

		} catch (IOException e) {
			System.err.println(e.toString());
		} finally {
			if (sslSocket != null) {
				try {
					sslSocket.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}

		return time;
	}
}
