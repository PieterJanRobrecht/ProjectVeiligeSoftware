package ssl;

import java.io.InputStream;
import java.util.Arrays;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import javax.net.ssl.SSLSocket;

public class HandlingThread extends Communicator implements Runnable {
	SSLSocket sslSocket;
	final BlockingQueue<String> queue;

	public HandlingThread(SSLSocket sslSocket2, BlockingQueue<String> queue2) {
		sslSocket = sslSocket2;
		queue = queue2;
	}

	public void run() {
		while (true) {
			try {
				String message = queue.take();

				switch (message) {
				case "AuthSP":
					authenticateServiceProvider();
					break;
				case "AuthCard":
					authenticateCard();
					break;
				default:
					break;
				}
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}

	private void authenticateCard() {
		// TODO Auto-generated method stub

	}

	private void authenticateServiceProvider() {
		System.out.println("Authenticating Service Provider");
		try {
			InputStream inputStream = sslSocket.getInputStream();

			String cert = null;
			for (int i = 0; i < 9; i++) {
				cert += receive(inputStream);
			}

			cert = cert.split("null")[1];

			byte[] certInBytes = hexStringToByteArray(cert);

			System.out.println("Cert in hex: " + cert);
			System.out.println("Cert: " + Arrays.toString(certInBytes));
			
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}
}
