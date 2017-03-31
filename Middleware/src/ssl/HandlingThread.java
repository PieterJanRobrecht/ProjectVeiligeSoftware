package ssl;

import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.Random;
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
				// Thread.sleep(500);
				String first = queue.peek();
				if (first != null && (first.equals("AuthSP") || first.equals("AuthCard") || first.equals("AuthSP2") || first.equals("ReleasingAttributes"))) {
					String message = queue.take();

					switch (message) {
					case "AuthSP":
						authenticateServiceProvider();
						break;
					case "AuthSP2":
						authenticateServiceProvider2();
						break;
					case "AuthCard":
						//authenticateCard();
						break;
					case "ReleasingAttributes":
						releaseAttributes();
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
	 * @throws InterruptedException
	 ***/
	private void authenticateServiceProvider() throws IOException, InterruptedException {
		System.out.println("Authenticating Service Provider");

		InputStream inputStream = sslSocket.getInputStream();
		OutputStream outputStream = sslSocket.getOutputStream();

		String cert = null;
		Thread.sleep(1000);
		int kappa = queue.size();
		for (int i = 0; i < kappa; i++) {
			String first = queue.peek();
			if (first != null && !first.equals("AuthSP") && !first.equals("AuthCard") && !first.equals("AuthSP2") && !first.equals("ReleasingAttributes")) {
				cert += queue.take();
				System.out.println(i + " -\t " + cert);
			} else if (first != null && (first.equals("AuthSP") || first.equals("AuthCard") || first.equals("AuthSP2") || first.equals("ReleasingAttributes"))) {
				first = queue.take();
				queue.put(first);
			}
		}
		cert = cert.split("null")[1];

		System.out.println(cert);
		byte[] certInBytes = hexStringToByteArray(cert);

		System.out.println("Cert in hex: " + cert);
		System.out.println("Cert: " + Arrays.toString(certInBytes));

		byte[] Ks = mwc.authenticateServiceProvider(certInBytes);
		Ks = cutOffNulls(Ks);

		String ks = bytesToHex(Ks);
		System.out.println(ks.length() + " || " + ks);
		String send1 = ks.substring(0, 95);
		String send2 = ks.substring(95, ks.length());
		System.out.println(send1 + send2);
		send(send1, outputStream);
		send(send2, outputStream);

		byte[] Emsg = mwc.getEmsg();

		Emsg = cutOffNulls(Emsg);

		String EMsg = bytesToHex(Emsg);
		System.out.println(EMsg.length() + " || " + EMsg);
		send(EMsg, outputStream);
	}

	private void authenticateServiceProvider2() throws IOException, InterruptedException {
		System.out.println("Authenticating Service Provider 2");

		InputStream inputStream = sslSocket.getInputStream();
		OutputStream outputStream = sslSocket.getOutputStream();

		Thread.sleep(1000);
		String inc = queue.take();
		System.out.println(inc);

		byte[] rec = hexStringToByteArray(inc);

		System.out.println(Arrays.toString(rec));

		byte[] resp = mwc.authenticateServiceProvider2(rec);
	}

	/***
	 * STAP 3
	 * 
	 * @throws IOException
	 * @throws InterruptedException
	 ***/
	private void authenticateCard() throws IOException, InterruptedException {
		System.out.println("Authenticating Card");
		InputStream inputStream = sslSocket.getInputStream();
		OutputStream outputStream = sslSocket.getOutputStream();

		String challenge = null;
		int kappa = 0;
		do {
			kappa = queue.size();
		} while (kappa == 0);
		for (int i = 0; i < kappa; i++) {
			String first = queue.peek();
			if (first != null && !first.equals("AuthSP") && !first.equals("AuthCard") && !first.equals("AuthSP2") && !first.equals("ReleasingAttributes")) {
				challenge += queue.take();
				System.out.println(i + " -\t " + challenge);
			} else if (first != null && (first.equals("AuthSP") || first.equals("AuthCard") || first.equals("AuthSP2") || first.equals("ReleasingAttributes"))) {
				first = queue.take();
				queue.put(first);
			}
		}
		challenge = challenge.split("null")[1];

		System.out.println("Sending to card: " + Arrays.toString(hexStringToByteArray(challenge)) + " with length " + hexStringToByteArray(challenge).length);
		// Send challenge to card
		byte[] Emsg = mwc.authenticateCard(hexStringToByteArray(challenge));

	}
	
	/**
	 * STAP 4: TODO
	 * @throws IOException 
	 * @throws InterruptedException 
	 */
	public void releaseAttributes() throws IOException, InterruptedException {
		System.out.println("Requesting release of Attributes");

		InputStream inputStream = sslSocket.getInputStream();
		OutputStream outputStream = sslSocket.getOutputStream();

		Thread.sleep(1000);
		String inc = queue.take();
		System.out.println(inc);

		byte[] rec = hexStringToByteArray(inc);

		System.out.println(Arrays.toString(rec));

		byte[] resp = mwc.requestReleaseOfAttributes(rec);
	}

	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	public static String bytesToHex(byte[] in) {
		final StringBuilder builder = new StringBuilder();
		for (byte b : in) {
			builder.append(String.format("%02x", b));
		}
		return builder.toString();
	}

	private byte[] cutOffNulls(byte[] data) {
		short length = (short) data.length;
		for (short i = length; i > 0; i--) {
			byte kappa = data[(short) (i - 1)];
			if (kappa != (byte) 0) {
				length = (short) (i);
				break;
			}
		}

		byte[] cleanedData = new byte[length];
		for (int i = 0; i < length; i++) {
			cleanedData[i] = data[i];
		}

		return cleanedData;
	}

}
