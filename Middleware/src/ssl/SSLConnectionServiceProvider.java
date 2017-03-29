package ssl;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import be.msec.client.connection.IConnection;
import controller.MiddlewareController;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * TODO getjoepte shizzle vervangen
 * 
 * @author rhino
 *
 */
public class SSLConnectionServiceProvider extends Communicator {
	SSLSocketFactory sslSocketFactory;
	SSLSocket sslSocket;
	MiddlewareController mwc;
	IConnection connection;

	final BlockingQueue<String> queue = new LinkedBlockingQueue<String>();

	public SSLConnectionServiceProvider(MiddlewareController mwc, IConnection connection) {
		// System.setProperty("javax.net.ssl.keyStore", "ssl/Obama");
		// System.setProperty("javax.net.ssl.keyStorePassword", "ThankYou");
		System.setProperty("javax.net.ssl.trustStore", "ssl/client_truststore");
		System.setProperty("javax.net.ssl.trustStorePassword", "client_truststore");

		this.mwc = mwc;

		sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		sslSocket = null;

		this.connection = connection;
	}

	private void startHandelingThread() {
		Thread t = new Thread(new HandlingThread(sslSocket, queue, mwc));
		t.start();
	}

	private void startListeningThread() {
		Thread t = new Thread(new Runnable() {

			@Override
			public void run() {
				while (true) {
					try {
						InputStream inputStream = sslSocket.getInputStream();
						OutputStream outputStream = sslSocket.getOutputStream();

						String message = receive(inputStream);
						queue.put(message);

					} catch (IOException e) {
						e.printStackTrace();
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
				}
			}

		});
		t.start();
	}

	public void connect() {
		try {
			sslSocket = (SSLSocket) sslSocketFactory.createSocket("localhost", 1338);
			sslSocket.startHandshake();

			startListeningThread();
			startHandelingThread();

		} catch (IOException e) {
			e.printStackTrace();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}