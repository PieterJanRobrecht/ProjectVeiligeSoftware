package ssl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Arrays;
import java.util.Random;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

public class SSLConnectionMiddleware extends Communicator {
	SSLSocketFactory sslSocketFactory;
	SSLSocket sslSocket;

	public SSLConnectionMiddleware() {
		sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		sslSocket = null;
	}

	public byte[][] authenticateServiceProvider() {
		byte[][] returnValue = null;
		try {
			sslSocket = (SSLSocket) sslSocketFactory.createSocket("localhost", 1340);
			sslSocket.startHandshake();

			InputStream inputStream = sslSocket.getInputStream();
			OutputStream outputStream = sslSocket.getOutputStream();

			send("0", outputStream);
			String auth = receive(inputStream);
			System.out.println(auth);

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
		return returnValue;
	}

	public byte[][] authenticateCard() {
		byte[][] returnValue = null;

		try {
			sslSocket = (SSLSocket) sslSocketFactory.createSocket("localhost", 1340);
			sslSocket.startHandshake();

			InputStream inputStream = sslSocket.getInputStream();
			OutputStream outputStream = sslSocket.getOutputStream();

			send("1", outputStream);
			String challenge = createChallenge();
			String auth = receive(inputStream);
			System.out.println(auth);

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

		return returnValue;

	}

	private String createChallenge() {
		Random randomGenerator = new Random();
		int randomInt = randomGenerator.nextInt(256);
		System.out.println("Generating challenge for card: " + String.valueOf(randomInt));
		return String.valueOf(randomInt);
	}
}
