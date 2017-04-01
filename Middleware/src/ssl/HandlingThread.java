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
				if (first != null && (first.equals("AuthSP") || first.equals("AuthCard") || first.equals("AuthSP2") || first.equals("ReleaseAttributes"))) {
					String message = queue.take();

					switch (message) {
					case "AuthSP":
						authenticateServiceProvider();
						break;
					case "AuthSP2":
						authenticateServiceProvider2();
						break;
					case "AuthCard":
						authenticateCard();
						break;
					case "ReleaseAttributes":
						System.out.println("wtf..");
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
			if (first != null && !first.equals("AuthSP") && !first.equals("AuthCard") && !first.equals("AuthSP2") && !first.equals("ReleaseAttributes")) {
				cert += queue.take();
			} else if (first != null && (first.equals("AuthSP") || first.equals("AuthCard") || first.equals("AuthSP2") || first.equals("ReleaseAttributes"))) {
				first = queue.take();
				queue.put(first);
			}
		}
		cert = cert.split("null")[1];

		byte[] certInBytes = hexStringToByteArray(cert);

		byte[] Ks = mwc.authenticateServiceProvider(certInBytes);
		Ks = cutOffNulls(Ks);
		System.out.println("\tLength in bytes: " + Ks.length);
		mwc.addText("MW -> SP \n\t Versturen van de nieuwe symmetrische sleutel \n\t In bytes " + Arrays.toString(Ks));
		String ks = bytesToHex(Ks);
		System.out.println("\tks value: " + ks.length() + " || " + ks);
		String send1 = ks.substring(0, 95);
		String send2 = ks.substring(95, ks.length());
		System.out.println(send1 + send2);
		send(send1, outputStream);
		send(send2, outputStream);

		byte[] Emsg = mwc.getEmsg();

		Emsg = cutOffNulls(Emsg);

		String EMsg = bytesToHex(Emsg);
		System.out.println("\tEMsg value: " + EMsg.length() + " || " + EMsg);
		mwc.addText("MW -> SP \n\t Versturen van Emsg \n\t In encrypted bytes " + Arrays.toString(Emsg));
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
		mwc.addText("SP -> MW \n\t Ontvangen van de response \n\t In bytes " + Arrays.toString(rec));

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
		mwc.addText("### START STAP 3 ###");
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
			if (first != null && !first.equals("AuthSP") && !first.equals("AuthCard") && !first.equals("AuthSP2") && !first.equals("ReleaseAttributes")) {
				challenge += queue.take();
			} else if (first != null && (first.equals("AuthSP") || first.equals("AuthCard") || first.equals("AuthSP2") || first.equals("ReleaseAttributes"))) {
				first = queue.take();
				queue.put(first);
			}
		}
		challenge = challenge.split("null")[1];

		mwc.addText("SP -> MW \n\t Ontvangen van de challenge \n\t In encrypted bytes " + Arrays.toString(hexStringToByteArray(challenge)));
		System.out.println("Sending to card: " + Arrays.toString(hexStringToByteArray(challenge)) + " with length " + hexStringToByteArray(challenge).length);

		// Send challenge to card
		byte[] Emsg = mwc.authenticateCard(hexStringToByteArray(challenge));
		Emsg = cutOffNulls(Emsg);
		System.out.println("Received: " + Arrays.toString(Emsg) + " \n\t with length: " + Emsg.length);

		mwc.addText("MW -> SP \n\t Verzenden van Emsg \n\t In encrypted bytes " + Arrays.toString(Emsg));
		String toSend = bytesToHex(Emsg);
		System.out.println("Sending " + toSend + " \n\t with length " + toSend.length());
		send(toSend.substring(0, 100), outputStream);
		send(toSend.substring(100, 200), outputStream);
		send(toSend.substring(200, 300), outputStream);
		send(toSend.substring(300, 400), outputStream);
		send(toSend.substring(400, 500), outputStream);
		send(toSend.substring(500, 600), outputStream);
		send(toSend.substring(600, 700), outputStream);
		send(toSend.substring(700, 800), outputStream);
		send(toSend.substring(800, 900), outputStream);
		send(toSend.substring(900, 1000), outputStream);
		send(toSend.substring(1000, toSend.length()), outputStream);
		mwc.addText("### EINDE STAP 3 ###");
	}

	/**
	 * STAP 4: TODO
	 * 
	 * @throws IOException
	 * @throws InterruptedException
	 */
	public void releaseAttributes() throws IOException, InterruptedException {
		System.out.println("Requesting release of Attributes");

		InputStream inputStream = sslSocket.getInputStream();
		OutputStream outputStream = sslSocket.getOutputStream();

		Thread.sleep(1000);
		String inc = queue.take();

		byte[] rec = hexStringToByteArray(inc);
		mwc.addText("SP -> MW \n\t Ontvangen query \n\t Query " + Arrays.toString(rec));
		System.out.println("\tRelease attributes - rec: " + Arrays.toString(rec));

		byte[] resp = mwc.requestReleaseOfAttributes(rec);
		String toSend = bytesToHex(resp);
		send(toSend.substring(0, 100), outputStream);
		send(toSend.substring(100, 200), outputStream);
		send(toSend.substring(200, 300), outputStream);
		send(toSend.substring(300, 400), outputStream);
		send(toSend.substring(400, 500), outputStream);
		send(toSend.substring(500, toSend.length()), outputStream);
		mwc.addText("### EINDE STAP 4 ###");
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
