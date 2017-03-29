package ssl;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.io.OutputStream;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import javax.net.ssl.SSLSocket;

import controller.MiddlewareController;

public class HandlingThread extends Communicator implements Runnable {
	SSLSocket sslSocket;
	final BlockingQueue<String> queue;
	MiddlewareController mwc;

	public HandlingThread(SSLSocket sslSocket2, BlockingQueue<String> queue2, MiddlewareController mwc) {
		sslSocket = sslSocket2;
		queue = queue2;
		this.mwc = mwc;
	}

	public void run() {
		while (true) {
			try {
				if (queue.peek().equals("AuthSP") || queue.peek().equals("AuthCard")) {
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
				}
			} catch (InterruptedException | IOException e) {
				e.printStackTrace();
			}
		}
	}

	/***
	 * STAP 2
	 * 
	 * @throws IOException
	 ***/
	private void authenticateServiceProvider() throws IOException {
		try {
			System.out.println("Authenticating Service Provider");

			InputStream inputStream = sslSocket.getInputStream();

			String cert = null;
			for (int i = 0; i < queue.size(); i++) {
				if (!queue.peek().equals("AuthSP") && !queue.peek().equals("AuthCard")) {
					cert += queue.take();
					System.out.println(i + " -\t " + cert);
				}
			}

			System.out.println(cert);

			byte[] certInBytes = hexStringToByteArray(cert);

			System.out.println("Cert in hex: " + cert);
			System.out.println("Cert: " + Arrays.toString(certInBytes));

			mwc.authenticateServiceProvider(certInBytes);

		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/***
	 * STAP 3
	 * 
	 * @throws IOException
	 ***/
	private void authenticateCard() throws IOException {
		// TODO Auto-generated method stub
		System.out.println("Authenticating Card");
		InputStream inputStream = sslSocket.getInputStream();
		OutputStream outputStream = sslSocket.getOutputStream();
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
