package ssl;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
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
import java.util.Observable;

/**
 * TODO getjoepte shizzle vervangen
 * 
 * @author rhino
 *
 */
public class SSLConnectionServiceProviderAsync extends Observable {
	SSLSocketFactory sslSocketFactory;
	SSLSocket sslSocket;
	byte[] data = new byte[100];
	int bytesLeft, bytesExpected, chunkReceived;

	String task = null;

	public SSLConnectionServiceProviderAsync() {
		// System.setProperty("javax.net.ssl.keyStore", "ssl/Obama");
		// System.setProperty("javax.net.ssl.keyStorePassword", "ThankYou");
		System.setProperty("javax.net.ssl.trustStore", "ssl/client_truststore");
		System.setProperty("javax.net.ssl.trustStorePassword", "client_truststore");

		sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		sslSocket = null;
		System.out.println("DEBUG constructor done");
	}

	public void setValue(String task) {
		System.out.println("Setting task: " + task);
		this.task = task;
		setChanged();
		notifyObservers();
	}

	public String getValue() {
		return task;
	}

	public void fetchTask() {
		System.out.println("Initializing fetchTask");
		Thread t = new Thread(new Runnable() {
			public void run() {
				try {
					sslSocket = (SSLSocket) sslSocketFactory.createSocket("localhost", 1338);
					sslSocket.startHandshake();

					InputStream inputStream = sslSocket.getInputStream();
					OutputStream outputStream = sslSocket.getOutputStream();

					System.out.println("Sending fetch task request");
					send("1", outputStream);
					setValue(receive(inputStream));

					inputStream.close();
					outputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				} catch (Exception e) {
					e.printStackTrace();
				} finally {
					if (sslSocket != null) {
						try {
							sslSocket.close();
						} catch (IOException e) {
							e.printStackTrace();
						}
					}
				}
			}
		});
		
		t.run();
	}

	protected void send(String message, OutputStream outputStream) throws IOException {
		if (message.length() > 100)
			throw new IndexOutOfBoundsException("Message length > 100.");

		char[] messageArray = message.toCharArray();

		for (int i = 0; i < message.length(); i++) {
			data[i] = (byte) messageArray[i];
		}

		for (int i = message.length(); i < 100; i++) {
			data[i] = 32;
		}

		outputStream.write(data);
	}

	protected String receive(InputStream inputStream) throws IOException {
		bytesLeft = bytesExpected = 100;

		while (bytesLeft > 0) {
			chunkReceived = inputStream.read(data, bytesExpected - bytesLeft, bytesLeft);
			if (chunkReceived == -1) {
				throw new IOException("Datastream closed.");
			} else {
				bytesLeft -= chunkReceived;
			}
		}

		return new String(data).trim();
	}
}