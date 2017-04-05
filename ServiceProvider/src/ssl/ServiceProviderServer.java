package ssl;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

import org.bouncycastle.asn1.isismtt.x509.AdditionalInformationSyntax;

import controller.ServiceProviderController;

import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateFactory;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.io.*;
import java.lang.reflect.Array;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;
import java.util.Random;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

public class ServiceProviderServer extends Communicator implements Runnable {
	private SSLSocket sslSocket;
	private SSLServerSocket sslServerSocket;

	private SecretKey Ks;

	// dummy certificate
	private byte[] certificate = new byte[] { (byte) 48, (byte) -126, (byte) 1, (byte) -67, (byte) 48, (byte) -126,
			(byte) 1, (byte) 103, (byte) -96, (byte) 3, (byte) 2, (byte) 1, (byte) 2, (byte) 2, (byte) 5, (byte) 0,
			(byte) -73, (byte) -43, (byte) 96, (byte) -107, (byte) 48, (byte) 13, (byte) 6, (byte) 9, (byte) 42,
			(byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 5, (byte) 5, (byte) 0,
			(byte) 48, (byte) 100, (byte) 49, (byte) 11, (byte) 48, (byte) 9, (byte) 6, (byte) 3, (byte) 85, (byte) 4,
			(byte) 6, (byte) 19, (byte) 2, (byte) 66, (byte) 69, (byte) 49, (byte) 13, (byte) 48, (byte) 11, (byte) 6,
			(byte) 3, (byte) 85, (byte) 4, (byte) 7, (byte) 12, (byte) 4, (byte) 71, (byte) 101, (byte) 110, (byte) 116,
			(byte) 49, (byte) 25, (byte) 48, (byte) 23, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 10, (byte) 12,
			(byte) 16, (byte) 75, (byte) 97, (byte) 72, (byte) 111, (byte) 32, (byte) 83, (byte) 105, (byte) 110,
			(byte) 116, (byte) 45, (byte) 76, (byte) 105, (byte) 101, (byte) 118, (byte) 101, (byte) 110, (byte) 49,
			(byte) 20, (byte) 48, (byte) 18, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 11, (byte) 12, (byte) 11,
			(byte) 86, (byte) 97, (byte) 107, (byte) 103, (byte) 114, (byte) 111, (byte) 101, (byte) 112, (byte) 32,
			(byte) 73, (byte) 84, (byte) 49, (byte) 21, (byte) 48, (byte) 19, (byte) 6, (byte) 3, (byte) 85, (byte) 4,
			(byte) 3, (byte) 12, (byte) 12, (byte) 74, (byte) 97, (byte) 110, (byte) 32, (byte) 86, (byte) 111,
			(byte) 115, (byte) 115, (byte) 97, (byte) 101, (byte) 114, (byte) 116, (byte) 48, (byte) 32, (byte) 23,
			(byte) 13, (byte) 49, (byte) 48, (byte) 48, (byte) 50, (byte) 50, (byte) 52, (byte) 48, (byte) 57,
			(byte) 52, (byte) 51, (byte) 48, (byte) 50, (byte) 90, (byte) 24, (byte) 15, (byte) 53, (byte) 49,
			(byte) 55, (byte) 57, (byte) 48, (byte) 49, (byte) 48, (byte) 57, (byte) 49, (byte) 57, (byte) 50,
			(byte) 57, (byte) 52, (byte) 50, (byte) 90, (byte) 48, (byte) 100, (byte) 49, (byte) 11, (byte) 48,
			(byte) 9, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 6, (byte) 19, (byte) 2, (byte) 66, (byte) 69,
			(byte) 49, (byte) 13, (byte) 48, (byte) 11, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 7, (byte) 12,
			(byte) 4, (byte) 71, (byte) 101, (byte) 110, (byte) 116, (byte) 49, (byte) 25, (byte) 48, (byte) 23,
			(byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 10, (byte) 12, (byte) 16, (byte) 75, (byte) 97, (byte) 72,
			(byte) 111, (byte) 32, (byte) 83, (byte) 105, (byte) 110, (byte) 116, (byte) 45, (byte) 76, (byte) 105,
			(byte) 101, (byte) 118, (byte) 101, (byte) 110, (byte) 49, (byte) 20, (byte) 48, (byte) 18, (byte) 6,
			(byte) 3, (byte) 85, (byte) 4, (byte) 11, (byte) 12, (byte) 11, (byte) 86, (byte) 97, (byte) 107,
			(byte) 103, (byte) 114, (byte) 111, (byte) 101, (byte) 112, (byte) 32, (byte) 73, (byte) 84, (byte) 49,
			(byte) 21, (byte) 48, (byte) 19, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 3, (byte) 12, (byte) 12,
			(byte) 74, (byte) 97, (byte) 110, (byte) 32, (byte) 86, (byte) 111, (byte) 115, (byte) 115, (byte) 97,
			(byte) 101, (byte) 114, (byte) 116, (byte) 48, (byte) 92, (byte) 48, (byte) 13, (byte) 6, (byte) 9,
			(byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 1,
			(byte) 5, (byte) 0, (byte) 3, (byte) 75, (byte) 0, (byte) 48, (byte) 72, (byte) 2, (byte) 65, (byte) 0,
			(byte) -73, (byte) -43, (byte) 96, (byte) -107, (byte) 82, (byte) 25, (byte) -66, (byte) 34, (byte) 5,
			(byte) -58, (byte) 75, (byte) -39, (byte) -54, (byte) 43, (byte) 25, (byte) -117, (byte) 80, (byte) -62,
			(byte) 51, (byte) 19, (byte) 59, (byte) -70, (byte) -100, (byte) 85, (byte) 24, (byte) -57, (byte) 108,
			(byte) -98, (byte) -2, (byte) 1, (byte) -80, (byte) -39, (byte) 63, (byte) 93, (byte) 112, (byte) 7,
			(byte) 4, (byte) 18, (byte) -11, (byte) -98, (byte) 17, (byte) 126, (byte) -54, (byte) 27, (byte) -56,
			(byte) 33, (byte) 77, (byte) -111, (byte) -74, (byte) -78, (byte) 88, (byte) 70, (byte) -22, (byte) -3,
			(byte) 15, (byte) 16, (byte) 37, (byte) -18, (byte) 92, (byte) 74, (byte) 124, (byte) -107, (byte) -116,
			(byte) -125, (byte) 2, (byte) 3, (byte) 1, (byte) 0, (byte) 1, (byte) 48, (byte) 13, (byte) 6, (byte) 9,
			(byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 5,
			(byte) 5, (byte) 0, (byte) 3, (byte) 65, (byte) 0, (byte) 33, (byte) 97, (byte) 121, (byte) -25, (byte) 43,
			(byte) -47, (byte) 113, (byte) -104, (byte) -11, (byte) -42, (byte) -46, (byte) -17, (byte) 1, (byte) -38,
			(byte) 50, (byte) 59, (byte) -63, (byte) -74, (byte) -33, (byte) 90, (byte) 92, (byte) -59, (byte) 99,
			(byte) -17, (byte) -60, (byte) 17, (byte) 25, (byte) 79, (byte) 68, (byte) 68, (byte) -57, (byte) -8,
			(byte) -64, (byte) 35, (byte) -19, (byte) -114, (byte) 110, (byte) -116, (byte) 31, (byte) -126, (byte) -24,
			(byte) 54, (byte) 71, (byte) 82, (byte) -53, (byte) -78, (byte) -84, (byte) -45, (byte) -83, (byte) 87,
			(byte) 68, (byte) 124, (byte) -1, (byte) -128, (byte) -49, (byte) 124, (byte) 103, (byte) 28, (byte) 56,
			(byte) -114, (byte) -10, (byte) 97, (byte) -78, (byte) 54 };

	private byte[] dummyPrivExponent = new byte[] { (byte) 0x64, (byte) 0xc2, (byte) 0x8d, (byte) 0xcf, (byte) 0xa1,
			(byte) 0x1a, (byte) 0x7e, (byte) 0x6a, (byte) 0xc9, (byte) 0x42, (byte) 0xf7, (byte) 0xb6, (byte) 0xad,
			(byte) 0x86, (byte) 0xdb, (byte) 0xf5, (byte) 0x20, (byte) 0x7c, (byte) 0xcd, (byte) 0x4d, (byte) 0xe9,
			(byte) 0xfb, (byte) 0x2e, (byte) 0x2b, (byte) 0x99, (byte) 0xfa, (byte) 0x29, (byte) 0x1e, (byte) 0xd9,
			(byte) 0xbd, (byte) 0xf9, (byte) 0xb2, (byte) 0x77, (byte) 0x9e, (byte) 0x3e, (byte) 0x1a, (byte) 0x60,
			(byte) 0x67, (byte) 0x8e, (byte) 0xbd, (byte) 0xae, (byte) 0x36, (byte) 0x54, (byte) 0x4a, (byte) 0x11,
			(byte) 0xc2, (byte) 0x2e, (byte) 0x7c, (byte) 0x9e, (byte) 0xc3, (byte) 0xcb, (byte) 0xba, (byte) 0x65,
			(byte) 0x2b, (byte) 0xc5, (byte) 0x1b, (byte) 0x6f, (byte) 0x4f, (byte) 0x54, (byte) 0xe1, (byte) 0xff,
			(byte) 0xc3, (byte) 0x18, (byte) 0x81 };
	private byte[] dummyPrivModulus = new byte[] { (byte) 0x8d, (byte) 0x08, (byte) 0x00, (byte) 0x7e, (byte) 0x39,
			(byte) 0xb1, (byte) 0x52, (byte) 0x4e, (byte) 0xc8, (byte) 0x90, (byte) 0x90, (byte) 0x37, (byte) 0x93,
			(byte) 0xd1, (byte) 0xcc, (byte) 0x33, (byte) 0xa8, (byte) 0x8d, (byte) 0xd5, (byte) 0x88, (byte) 0x7d,
			(byte) 0x5c, (byte) 0xcc, (byte) 0x8a, (byte) 0x26, (byte) 0xaa, (byte) 0x05, (byte) 0x2d, (byte) 0x7c,
			(byte) 0xed, (byte) 0xd9, (byte) 0xc4, (byte) 0xec, (byte) 0x89, (byte) 0x4e, (byte) 0x27, (byte) 0x85,
			(byte) 0x9b, (byte) 0x33, (byte) 0x43, (byte) 0x72, (byte) 0xae, (byte) 0xe2, (byte) 0xc8, (byte) 0x4d,
			(byte) 0x7c, (byte) 0x04, (byte) 0x02, (byte) 0xcd, (byte) 0x46, (byte) 0xf0, (byte) 0x3b, (byte) 0xd8,
			(byte) 0xa0, (byte) 0xb9, (byte) 0xd1, (byte) 0x9d, (byte) 0x33, (byte) 0x44, (byte) 0xe1, (byte) 0xfa,
			(byte) 0x0d, (byte) 0xf6, (byte) 0x69 };

	final BlockingQueue<String> queue = new LinkedBlockingQueue<String>();
	private X509Certificate x509Certificate;
	private RSAPrivateKey spPrivateKey;
	private ServiceProviderController controller;

	public ServiceProviderServer(X509Certificate x509Certificate, RSAPrivateKey rsaPrivateKey,
			ServiceProviderController serviceProviderController) {
		this.x509Certificate = x509Certificate;
		this.spPrivateKey = rsaPrivateKey;
		this.controller = serviceProviderController;
	}

	public static String bytesToHex(byte[] in) {
		final StringBuilder builder = new StringBuilder();
		for (byte b : in) {
			builder.append(String.format("%02x", b));
		}
		return builder.toString();
	}

	@Override
	public void run() {
		System.setProperty("javax.net.ssl.keyStore", "ssl/server_keystore");
		System.setProperty("javax.net.ssl.keyStorePassword", "server_keystore");
		System.setProperty("javax.net.ssl.trustStore", "ssl/server_truststore");
		System.setProperty("javax.net.ssl.trustStorePassword", "server_truststore");

		InputStream inputStream = null;
		OutputStream outputStream = null;

		SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		sslServerSocket = null;

		try {
			sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(1338);
		} catch (IOException e) {
			System.err.println("Unable to initiate SSLServerSocket.");
			e.printStackTrace();
			System.exit(1);
		}

		try {

			// Krijgt connectie binnen van MW
			sslSocket = (SSLSocket) sslServerSocket.accept();
			sslSocket.setNeedClientAuth(false);
			SSLSession sslSession = sslSocket.getSession();
			// Hebben nu een connectie met MW die we open houden

			System.out.println("Got a connection with MW");

		} catch (IOException e) {
			e.printStackTrace();
		}

		startListeningThread();

		try {
			controller.addText("### BEGIN STAP 2 ###");
			// Begin Stap 2
			long startTime = System.currentTimeMillis();
			authenticateServiceProvider();
			long stopTime = System.currentTimeMillis();
			long elapsedTime = stopTime - startTime;
			System.out.println(elapsedTime);
			controller.addText("### EINDE STAP 2 ###");

			controller.addText("### BEGIN STAP 3 ###");
			// Begin stap 3
			startTime = System.currentTimeMillis();
			authenticateCard();
			stopTime = System.currentTimeMillis();
			elapsedTime = stopTime - startTime;
			System.out.println(elapsedTime);
			controller.addText("### EINDE STAP 3 ###");

		} catch (CertificateEncodingException e) {
			e.printStackTrace();
		}
	}

	public void restart() {
		if (sslSocket == null) {
			try {
				// Krijgt connectie binnen van MW
				sslSocket = (SSLSocket) sslServerSocket.accept();
				sslSocket.setNeedClientAuth(false);
				SSLSession sslSession = sslSocket.getSession();
				// Hebben nu een connectie met MW die we open houden

				System.out.println("Got a connection with MW");

			} catch (IOException e) {
				e.printStackTrace();
			}

			startListeningThread();

		} else {
			try {
				controller.addText("### BEGIN STAP 2 ###");
				// Begin Stap 2
				authenticateServiceProvider();
				controller.addText("### EINDE STAP 2 ###");

				controller.addText("### BEGIN STAP 3 ###");
				// Begin stap 3
				authenticateCard();
				controller.addText("### EINDE STAP 3 ###");

			} catch (CertificateEncodingException e) {
				e.printStackTrace();
			}
		}
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

	/***
	 * STAP 2
	 * 
	 * @throws CertificateEncodingException
	 * @throws java.security.cert.CertificateEncodingException
	 ***/
	private void authenticateServiceProvider() throws CertificateEncodingException {
		System.out.println("Authenticating Service Provider");
		InputStream inputStream = null;
		OutputStream outputStream = null;
		try {
			inputStream = sslSocket.getInputStream();
			outputStream = sslSocket.getOutputStream();

			controller.addText("SP -> MW \n\t Authentiseer Service Provider \n\t Met certificaat "
					+ Arrays.toString(x509Certificate.getEncoded()));
			send("AuthSP", outputStream);

			System.out.println("Client connected to fetch certificate, returning "
					+ Arrays.toString(x509Certificate.getEncoded()));

			String test = bytesToHex(x509Certificate.getEncoded());
			send(test.substring(0, 100), outputStream);
			send(test.substring(100, 200), outputStream);
			send(test.substring(200, 300), outputStream);
			send(test.substring(300, 400), outputStream);
			send(test.substring(400, 500), outputStream);
			send(test.substring(500, 600), outputStream);
			send(test.substring(600, 700), outputStream);
			send(test.substring(700, test.length()), outputStream);

			boolean gaan = true;
			while (gaan) {
				String first = queue.peek();
				if (first != null) {
					gaan = false;
				} else {
					Thread.sleep(250);
				}
			}

			String msg = queue.take();
			msg += queue.take();
			byte[] inc = hexStringToByteArray(msg);

			controller.addText("MW -> SP \n\t Ontvangen van de symmetrische sleutel \n\t In encrypted bytes "
					+ Arrays.toString(inc));
			System.out.println("\tPayload SYMMETRIC KEY: " + Arrays.toString(inc));

			// String mod = bytesToHex(dummyPrivModulus);
			// String exp = bytesToHex(dummyPrivExponent);
			// RSAPrivateKey secretKey = (RSAPrivateKey) generatePrivateKey(mod,
			// exp);

			byte[] data = slice(inc, 0, 64);

			Cipher asymCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			asymCipher.init(Cipher.DECRYPT_MODE, spPrivateKey);

			byte[] decryptedData = new byte[256];
			asymCipher.doFinal(data, (short) 0, (short) data.length, decryptedData, (short) 0);
			controller.addText(
					"SP \n\t Symmetrische sleutel decrypteren \n\t In bytes " + Arrays.toString(decryptedData));

			byte[] returnData = slice(decryptedData, 0, 16);
			SecretKey originalKey = new SecretKeySpec(returnData, 0, returnData.length, "AES");
			Ks = originalKey;
			System.out.println("\tKS: " + Arrays.toString(Ks.getEncoded()));

			gaan = true;
			while (gaan) {
				String first = queue.peek();
				if (first != null) {
					gaan = false;
				} else {
					Thread.sleep(250);
				}
			}

			msg = queue.take();
			inc = hexStringToByteArray(msg);
			controller.addText("MW -> SP \n\t Ontvangen van Emsg \n\t In encrypted bytes " + Arrays.toString(inc));
			System.out.println("debug - " + Arrays.toString(inc));
			data = slice(inc, 0, 16);

			Cipher symCipher = Cipher.getInstance("AES/CBC/NoPadding");
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);
			symCipher.init(Cipher.DECRYPT_MODE, Ks, ivspec);

			decryptedData = new byte[256];
			symCipher.doFinal(data, (short) 0, (short) data.length, decryptedData, (short) 0);

			returnData = cutOffNulls(decryptedData);
			System.out.println("\treturnData: " + Arrays.toString(returnData));
			controller.addText("SP \n\t Decrypteren van de subject en challenge \n\t Subject " + returnData[1]
					+ " \n\t Challenge " + returnData[0]);
			byte[] subject = x509Certificate.getSubjectDN().getName().getBytes();

			if (returnData[1] == subject[0]) {
				controller.addText("SP \n\t Subjects zijn gelijk, tijd om challenge uit te voeren");
				int kappa = ((short) returnData[0]) + 1;
				System.out.println(kappa);
				controller.addText("SP \n\t Challenge met 1 verhoogt \n\t Response " + kappa);
				byte[] encryptedData = symEncrypt(kappa, Ks);
				controller.addText("SP \n\t Symmetrisch encrypteren van de response \n\t In bytes "
						+ Arrays.toString(encryptedData));
				System.out.println("\tdebug encryptedData - " + Arrays.toString(encryptedData));
				send("AuthSP2", outputStream);
				controller.addText(
						"SP -> MW \n\t Verzenden van de response \n\t In bytes " + Arrays.toString(encryptedData));
				send(bytesToHex(encryptedData), outputStream);
			} else {
				System.out.println("\t!!\treturndata is not subject[0]");
				System.out.println("\tsubject byte[]: " + Arrays.toString(subject));
			}

		} catch (IOException e) {
			e.printStackTrace();
		} catch (InterruptedException e) {
			e.printStackTrace();
		} catch (ShortBufferException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
	}

	/*** STAP 3 ***/
	private void authenticateCard() {
		System.out.println("Authenticating Card");
		InputStream inputStream = null;
		OutputStream outputStream = null;
		try {
			inputStream = sslSocket.getInputStream();
			outputStream = sslSocket.getOutputStream();

			send("AuthCard", outputStream);

			int c = generateChallenge();
			controller.addText("SP \n\t Challenge gemaakt \n\t Challenge " + c);
			System.out.println("Original challenge: " + c + "\n\t in bytes: "
					+ Arrays.toString(BigInteger.valueOf(c).toByteArray()));
			byte[] encrypted = symEncrypt(c, Ks);
			String message = bytesToHex(encrypted);
			System.out.println("Sending encrypted challenge: " + Arrays.toString(encrypted));
			System.out.println("Or in hex: " + message + " with length " + message.length());
			controller.addText("SP \n\t Encrypteren van de challenge \n\t In bytes " + Arrays.toString(encrypted));
			controller.addText(
					"SP -> MW \n\t Verzenden van challenge \n\t In encrypted bytes " + Arrays.toString(encrypted));
			send(message, outputStream);

			boolean gaan = true;
			while (gaan) {
				String first = queue.peek();
				if (first != null) {
					gaan = false;
				} else {
					Thread.sleep(250);
				}
			}
			// Receive response from card
			String responseString = null;
			int kappa = 0;
			do {
				kappa = queue.size();
			} while (kappa == 0);
			for (int i = 0; i < kappa; i++) {
				String first = queue.peek();
				if (first != null && !first.equals("AuthSP") && !first.equals("AuthCard") && !first.equals("AuthSP2")
						&& !first.equals("ReleaseAttributes")) {
					responseString += queue.take();
				} else if (first != null && (first.equals("AuthSP") || first.equals("AuthCard")
						|| first.equals("AuthSP2") || first.equals("ReleaseAttributes"))) {
					first = queue.take();
					queue.put(first);
				}
			}
			responseString = responseString.split("null")[1];

			byte[] response = hexStringToByteArray(responseString);
			controller.addText("MW -> SP \n\t Ontvangen van Emsg \n\t In encrypted bytes " + Arrays.toString(response));
			response = symDecrypt(response, Ks);
			controller.addText("SP \n\t Decrypteren van Emsg \n\t In bytes " + Arrays.toString(response));
			byte signLength = response[0];
			byte[] sign = new byte[signLength];
			int certLength = response.length - (1 + signLength);
			byte[] cert = new byte[certLength];
			for (int i = 0; i < signLength; i++) {
				int index = 1 + i;
				sign[i] = response[index];
			}
			for (int i = 0; i < certLength; i++) {
				int index = 1 + signLength + i;
				cert[i] = response[index];
			}
			controller.addText("SP \n\t Signature en certificaat bepalen \n\t Signature " + Arrays.toString(sign)
					+ " \n\t Certificate " + Arrays.toString(cert));

			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			InputStream in = new ByteArrayInputStream(cert);
			X509Certificate certificate = (X509Certificate) certFactory.generateCertificate(in);

			try {
				certificate.checkValidity();
				RSAPublicKey coPubKey = (RSAPublicKey) certificate.getPublicKey();
				controller.addText("SP \n\t Certificaat is geldig");
				byte[] hash = hash(BigInteger.valueOf(c).toByteArray());
				boolean verified = verifySig(hash, coPubKey, sign);
				if (verified) {
					controller.addText("SP \n\t Kaart is correct geauthenticeerd");
					System.out.println("The card had been verified");
				} else {
					controller.addText("SP \n\t Kaart is niet geauthenticeerd");
					System.out.println("The card was not verified");
				}
			} catch (CertificateExpiredException | CertificateNotYetValidException e) {
				System.out.println("The certificate was no longer valid");
				controller.addText("SP \n\t Certificaat is ongeldig");
			}

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private byte[] hash(byte[] c) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-1");
		md.update(c);

		byte byteData[] = md.digest();
		return byteData;
	}

	/*** STAP 4 ***/
	public void releaseAttributes(byte[] query) {
		long startTime = System.currentTimeMillis();
		System.out.println("Requesting release of attributes Card");
		InputStream inputStream = null;
		OutputStream outputStream = null;
		try {
			inputStream = sslSocket.getInputStream();
			outputStream = sslSocket.getOutputStream();
			controller.addText("SP -> MW \n\t Verzenden query \n\t Query " + Arrays.toString(query));
			send("ReleaseAttributes", outputStream);
			send(bytesToHex(query), outputStream);
			System.out.println("sent reqs");

			boolean gaan = true;
			while (gaan) {
				String first = queue.peek();
				if (first != null) {
					gaan = false;
				} else {
					Thread.sleep(250);
				}
			}

			String msg = queue.take();
			for (int i = 0; i < 5; i++) {
				msg += queue.take();
			}

			byte[] resp = hexStringToByteArray(msg);
			controller.addText(
					"MW -> SP \n\t Ontvangen van antwoord op query \n\t In encrypted bytes " + Arrays.toString(resp));
			byte[] decrypted = symDecrypt(resp, Ks);
			controller.addText("SP \n\t Decrypten van het antwoord \n\t In bytes " + Arrays.toString(decrypted));
			System.out.println(Arrays.toString(decrypted));

			byte[] nym = cutOffNulls(slice(decrypted, 0, (short) 64));
			controller.addText("SP \n\t Pseudoniem bepaalt \n\t In bytes " + Arrays.toString(nym));
			System.out.println("\tNym: " + Arrays.toString(nym));
			byte teller = decrypted[64];
			decrypted = slice(decrypted, (short) (64 + 1), decrypted.length);

			// query[0] = (name) ? (byte) 1 : (byte) 0;
			// query[1] = (adress) ? (byte) 1 : (byte) 0;
			// query[2] = (country) ? (byte) 1 : (byte) 0;
			// query[3] = (birthday) ? (byte) 1 : (byte) 0;
			// query[4] = (age) ? (byte) 1 : (byte) 0;
			// query[5] = (gender) ? (byte) 1 : (byte) 0;
			// query[6] = (foto) ? (byte) 1 : (byte) 0;

			byte[] name = null;
			byte[] adress = null;
			byte[] country = null;
			byte[] birthday = null;
			byte[] age = null;
			byte[] gender = null;
			byte[] foto = null;

			byte oudeTeller;

			controller.addText("SP \n\t Antwoord op query");
			for (int i = 0; i < 7; i++) {
				if (query[i] == (byte) 1) {
					switch (i) {
					case 0:
						oudeTeller = teller;
						name = slice(decrypted, (short) 0, (short) oudeTeller);
						teller = decrypted[oudeTeller];
						decrypted = slice(decrypted, (short) (oudeTeller + 1), decrypted.length);
						System.out.println("\tName: " + new String(name));
						controller.addText("\t\t Naam " + new String(name));
						break;
					case 1:
						oudeTeller = teller;
						adress = slice(decrypted, (short) 0, (short) oudeTeller);
						teller = decrypted[oudeTeller];
						decrypted = slice(decrypted, (short) (oudeTeller + 1), decrypted.length);
						System.out.println("\tAdress: " + new String(adress));
						controller.addText("\t\t Adres " + new String(adress));
						break;
					case 2:
						oudeTeller = teller;
						country = slice(decrypted, (short) 0, (short) oudeTeller);
						teller = decrypted[oudeTeller];
						decrypted = slice(decrypted, (short) (oudeTeller + 1), decrypted.length);
						System.out.println("\tCountry: " + new String(country));
						controller.addText("\t\t Land " + new String(country));
						break;
					case 3:
						oudeTeller = teller;
						birthday = slice(decrypted, (short) 0, (short) oudeTeller);
						teller = decrypted[oudeTeller];
						decrypted = slice(decrypted, (short) (oudeTeller + 1), decrypted.length);
						System.out.println("\tBirthday: " + new String(birthday));
						controller.addText("\t\t Verjaardag " + new String(birthday));
						break;
					case 4:
						oudeTeller = teller;
						age = slice(decrypted, (short) 0, (short) oudeTeller);
						teller = decrypted[oudeTeller];
						decrypted = slice(decrypted, (short) (oudeTeller + 1), decrypted.length);
						System.out.println("\tAge: " + new String(age));
						controller.addText("\t\t Leeftijd " + new String(age));
						break;
					case 5:
						oudeTeller = teller;
						gender = slice(decrypted, (short) 0, (short) oudeTeller);
						teller = decrypted[oudeTeller];
						decrypted = slice(decrypted, (short) (oudeTeller + 1), decrypted.length);
						System.out.println("\tGender: " + new String(gender));
						controller.addText("\t\t Geslacht " + new String(gender));
						break;
					case 6:
						oudeTeller = teller;
						foto = slice(decrypted, (short) 0, (short) oudeTeller);
						teller = decrypted[oudeTeller];
						decrypted = slice(decrypted, (short) (oudeTeller + 1), decrypted.length);
						System.out.println("\tFoto: " + Arrays.toString(foto));
						controller.addText("\t\t Foto " + Arrays.toString(foto));
						break;
					default:
						break;
					}
				}
			}
			long stopTime = System.currentTimeMillis();
			long elapsedTime = stopTime - startTime;
			System.out.println(elapsedTime);
			controller.addText("### EINDE STAP 4 ###");

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initVerify(key);
		signer.update(data);
		return (signer.verify(sig));

	}

	private byte[] symEncrypt(int c, SecretKey ks2)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, ShortBufferException,
			IllegalBlockSizeException, BadPaddingException, InvalidAlgorithmParameterException {
		Cipher symCipher = Cipher.getInstance("AES/CBC/NoPadding");
		byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		symCipher.init(Cipher.ENCRYPT_MODE, ks2, ivspec);

		BigInteger bigInt = BigInteger.valueOf(c);
		byte[] b = bigInt.toByteArray();
		byte[] toEncrypt = new byte[16];
		for (int i = 0; i < b.length; i++) {
			toEncrypt[i] = b[i];
		}

		byte[] cipherText = symCipher.doFinal(toEncrypt);

		return cipherText;
	}

	private byte[] symDecrypt(byte[] response, SecretKey ks2) throws IllegalBlockSizeException, BadPaddingException,
			InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchPaddingException {
		Cipher symCipher = Cipher.getInstance("AES/CBC/NoPadding");
		byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
		IvParameterSpec ivspec = new IvParameterSpec(iv);
		symCipher.init(Cipher.DECRYPT_MODE, ks2, ivspec);

		byte[] cipherText = symCipher.doFinal(response);

		return cipherText;
	}

	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	private int generateChallenge() {
		Random rand = new Random();
		int Low = -128; // inclusief
		int High = 128; // exclusief
		int challenge = rand.nextInt(High - Low) + Low;
		// int challenge = rand.nextInt(255);
		return challenge;
	}

	public static PrivateKey generatePrivateKey(String mod, String exp)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(new BigInteger(mod, 16), new BigInteger(exp, 16));
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PrivateKey privKey = fact.generatePrivate(keySpec);
		return privKey;
	}

	public byte[] slice(byte[] original, int offset, int end) {
		int length = (int) (end - offset);
		byte[] slice = new byte[length];

		for (int i = offset; i < end; i++) {
			int index = (int) (i - offset);
			slice[index] = original[i];
		}
		return slice;
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

	public X509Certificate getX509Certificate() {
		return x509Certificate;
	}

	public void setX509Certificate(X509Certificate x509Certificate) {
		this.x509Certificate = x509Certificate;
	}

	public RSAPrivateKey getSpPrivateKey() {
		return spPrivateKey;
	}

	public void setSpPrivateKey(RSAPrivateKey spPrivateKey) {
		this.spPrivateKey = spPrivateKey;
	}
}