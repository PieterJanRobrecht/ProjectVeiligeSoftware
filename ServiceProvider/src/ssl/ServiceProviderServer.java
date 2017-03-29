package ssl;

import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.security.cert.X509Certificate;
import java.io.*;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;

public class ServiceProviderServer extends Communicator implements Runnable {

	// dummy certificate
	private byte[] certificate = new byte[] { (byte) 48, (byte) -126, (byte) 1, (byte) -67, (byte) 48, (byte) -126, (byte) 1, (byte) 103, (byte) -96, (byte) 3, (byte) 2, (byte) 1, (byte) 2, (byte) 2, (byte) 5, (byte) 0, (byte) -73, (byte) -43, (byte) 96, (byte) -107, (byte) 48, (byte) 13, (byte) 6, (byte) 9, (byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 5, (byte) 5, (byte) 0, (byte) 48, (byte) 100, (byte) 49, (byte) 11, (byte) 48, (byte) 9, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 6, (byte) 19, (byte) 2, (byte) 66, (byte) 69, (byte) 49, (byte) 13, (byte) 48, (byte) 11, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 7, (byte) 12, (byte) 4, (byte) 71, (byte) 101, (byte) 110, (byte) 116, (byte) 49, (byte) 25, (byte) 48, (byte) 23, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 10, (byte) 12, (byte) 16, (byte) 75, (byte) 97, (byte) 72, (byte) 111, (byte) 32, (byte) 83, (byte) 105, (byte) 110, (byte) 116, (byte) 45, (byte) 76, (byte) 105, (byte) 101, (byte) 118, (byte) 101, (byte) 110, (byte) 49, (byte) 20, (byte) 48, (byte) 18, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 11, (byte) 12, (byte) 11, (byte) 86, (byte) 97, (byte) 107, (byte) 103, (byte) 114, (byte) 111, (byte) 101, (byte) 112, (byte) 32, (byte) 73, (byte) 84, (byte) 49, (byte) 21, (byte) 48, (byte) 19, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 3, (byte) 12, (byte) 12, (byte) 74, (byte) 97, (byte) 110, (byte) 32, (byte) 86, (byte) 111, (byte) 115, (byte) 115, (byte) 97, (byte) 101, (byte) 114, (byte) 116, (byte) 48, (byte) 32, (byte) 23, (byte) 13, (byte) 49, (byte) 48, (byte) 48, (byte) 50, (byte) 50, (byte) 52, (byte) 48, (byte) 57, (byte) 52, (byte) 51, (byte) 48, (byte) 50, (byte) 90, (byte) 24, (byte) 15, (byte) 53, (byte) 49, (byte) 55, (byte) 57, (byte) 48, (byte) 49, (byte) 48, (byte) 57, (byte) 49, (byte) 57, (byte) 50, (byte) 57, (byte) 52, (byte) 50, (byte) 90, (byte) 48, (byte) 100, (byte) 49, (byte) 11, (byte) 48, (byte) 9, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 6, (byte) 19, (byte) 2, (byte) 66, (byte) 69, (byte) 49, (byte) 13, (byte) 48, (byte) 11, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 7, (byte) 12, (byte) 4, (byte) 71, (byte) 101, (byte) 110, (byte) 116, (byte) 49, (byte) 25, (byte) 48, (byte) 23, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 10, (byte) 12, (byte) 16, (byte) 75, (byte) 97, (byte) 72, (byte) 111, (byte) 32, (byte) 83, (byte) 105, (byte) 110, (byte) 116, (byte) 45, (byte) 76, (byte) 105, (byte) 101, (byte) 118, (byte) 101, (byte) 110, (byte) 49, (byte) 20, (byte) 48, (byte) 18, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 11, (byte) 12, (byte) 11, (byte) 86, (byte) 97, (byte) 107, (byte) 103, (byte) 114, (byte) 111, (byte) 101, (byte) 112, (byte) 32, (byte) 73, (byte) 84, (byte) 49, (byte) 21, (byte) 48, (byte) 19, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 3, (byte) 12, (byte) 12, (byte) 74, (byte) 97, (byte) 110, (byte) 32, (byte) 86, (byte) 111, (byte) 115, (byte) 115, (byte) 97, (byte) 101, (byte) 114, (byte) 116, (byte) 48, (byte) 92, (byte) 48, (byte) 13, (byte) 6, (byte) 9, (byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 1, (byte) 5, (byte) 0, (byte) 3, (byte) 75, (byte) 0, (byte) 48, (byte) 72, (byte) 2, (byte) 65, (byte) 0, (byte) -73, (byte) -43, (byte) 96, (byte) -107, (byte) 82, (byte) 25, (byte) -66, (byte) 34, (byte) 5, (byte) -58, (byte) 75, (byte) -39, (byte) -54, (byte) 43, (byte) 25, (byte) -117, (byte) 80, (byte) -62, (byte) 51, (byte) 19, (byte) 59, (byte) -70, (byte) -100, (byte) 85, (byte) 24, (byte) -57, (byte) 108, (byte) -98, (byte) -2, (byte) 1, (byte) -80, (byte) -39, (byte) 63, (byte) 93, (byte) 112, (byte) 7, (byte) 4, (byte) 18, (byte) -11, (byte) -98, (byte) 17, (byte) 126, (byte) -54, (byte) 27, (byte) -56, (byte) 33, (byte) 77, (byte) -111, (byte) -74, (byte) -78, (byte) 88, (byte) 70, (byte) -22, (byte) -3, (byte) 15, (byte) 16, (byte) 37, (byte) -18, (byte) 92, (byte) 74, (byte) 124, (byte) -107, (byte) -116, (byte) -125, (byte) 2, (byte) 3, (byte) 1, (byte) 0, (byte) 1, (byte) 48, (byte) 13, (byte) 6, (byte) 9, (byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 5, (byte) 5, (byte) 0, (byte) 3, (byte) 65, (byte) 0, (byte) 33, (byte) 97, (byte) 121, (byte) -25, (byte) 43, (byte) -47, (byte) 113, (byte) -104, (byte) -11, (byte) -42, (byte) -46, (byte) -17, (byte) 1, (byte) -38, (byte) 50, (byte) 59, (byte) -63, (byte) -74, (byte) -33, (byte) 90, (byte) 92, (byte) -59, (byte) 99, (byte) -17, (byte) -60, (byte) 17, (byte) 25, (byte) 79, (byte) 68, (byte) 68, (byte) -57, (byte) -8, (byte) -64, (byte) 35, (byte) -19, (byte) -114, (byte) 110, (byte) -116, (byte) 31, (byte) -126, (byte) -24, (byte) 54, (byte) 71, (byte) 82, (byte) -53, (byte) -78, (byte) -84, (byte) -45, (byte) -83, (byte) 87, (byte) 68, (byte) 124, (byte) -1, (byte) -128, (byte) -49, (byte) 124, (byte) 103, (byte) 28, (byte) 56, (byte) -114, (byte) -10, (byte) 97, (byte) -78, (byte) 54 };

	String task = null;

	public ServiceProviderServer() {

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
		// TODO Auto-generated method stub
		System.setProperty("javax.net.ssl.keyStore", "ssl/server_keystore");
		System.setProperty("javax.net.ssl.keyStorePassword", "server_keystore");
		System.setProperty("javax.net.ssl.trustStore", "ssl/server_truststore");
		System.setProperty("javax.net.ssl.trustStorePassword", "server_truststore");

		InputStream inputStream = null;
		OutputStream outputStream = null;

		SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		SSLServerSocket sslServerSocket = null;

		try {
			sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(1338);
		} catch (IOException e) {
			System.err.println("Unable to initiate SSLServerSocket.");
			e.printStackTrace();
			System.exit(1);
		}

		System.out.println("SSLServerSocket initialized.");
		while (true) {
			try {
				SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
				sslSocket.setNeedClientAuth(false);
				SSLSession sslSession = sslSocket.getSession();

				// dit zorgt voor problemen :'( *sadface*
				// X509Certificate x509Certificate =
				// sslSession.getPeerCertificateChain()[0];
				// String username =
				// x509Certificate.getSubjectDN().getName().split("CN=")[1].split(",")[0];


				String[] message;

				while (true) {
					inputStream = sslSocket.getInputStream();
					outputStream = sslSocket.getOutputStream();
					message = receive(inputStream).split(" ");
					try {
						switch (Integer.parseInt(message[0])) {
						case 0:
							System.out.println("Client connected to fetch certificate, returning " + Arrays.toString(certificate));

							String test = bytesToHex(certificate);
							send(test.substring(0, 100), outputStream);
							send(test.substring(100, 200), outputStream);
							send(test.substring(200, 300), outputStream);
							send(test.substring(300, 400), outputStream);
							send(test.substring(400, 500), outputStream);
							send(test.substring(500, 600), outputStream);
							send(test.substring(600, 700), outputStream);
							send(test.substring(700, 800), outputStream);
							send(test.substring(800, test.length()), outputStream);
							break;
						case 1:
							System.out.println("Client connected to fetch task, waiting... ");
							while (task == null) {
								Thread.sleep(100);
							}
							send(task, outputStream);

							System.out.println("Task received, pushing: " + task);
							task = null;
							break;
						default:
							send("Invalid command.", outputStream);
							break;
						}
					} catch (NumberFormatException e) {
						send("Invalid command. " + e.getMessage(), outputStream);
					} catch (ArrayIndexOutOfBoundsException e) {
						send("Invalid command. " + e.getMessage(), outputStream);
					}
				}
			} catch (IOException e) {
				e.printStackTrace();
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				try {
					inputStream.close();
					outputStream.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
	}

	public void setTask(String task) {
		this.task = task;
	}
}

// private Server() {
// System.setProperty("javax.net.ssl.keyStore", "ssl/server_keystore");
// System.setProperty("javax.net.ssl.keyStorePassword", "server_keystore");
// System.setProperty("javax.net.ssl.trustStore", "ssl/server_truststore");
// System.setProperty("javax.net.ssl.trustStorePassword", "server_truststore");
//
// InputStream inputStream;
// OutputStream outputStream;
//
// SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory)
// SSLServerSocketFactory.getDefault();
// SSLServerSocket sslServerSocket = null;
//
// try {
// sslServerSocket = (SSLServerSocket)
// sslServerSocketFactory.createServerSocket(1337);
// } catch (IOException e) {
// System.err.println("Unable to initiate SSLServerSocket.");
// e.printStackTrace();
// System.exit(1);
// }
//
// while (true) {
// try {
// SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
// sslSocket.setNeedClientAuth(false);
// SSLSession sslSession = sslSocket.getSession();
//
// //dit zorgt voor problemen :'( *sadface*
// //X509Certificate x509Certificate = sslSession.getPeerCertificateChain()[0];
// //String username =
// x509Certificate.getSubjectDN().getName().split("CN=")[1].split(",")[0];
//
// inputStream = sslSocket.getInputStream();
// outputStream = sslSocket.getOutputStream();
//
// int unixTime = (int) (System.currentTimeMillis() / 1000);
//
// System.out.println("Client connected to fetch time, returning " + unixTime);
//
// /** TODO implement werking **/
// String[] message;
// int command;
//
// while (true) {
// message = receive(inputStream).split(" ");
// try {
// switch (Integer.parseInt(message[0])) {
// case 0:
// send("Kappa0", outputStream);
// break;
// case 1:
// send("Kappa1", outputStream);
// break;
// case 2:
// send("Kappa2", outputStream);
// break;
// case 3:
// send("Kappa3", outputStream);
// break;
// default:
// send("Invalid command.", outputStream);
// break;
// }
// } catch (NumberFormatException e) {
// send("Invalid command. " + e.getMessage(), outputStream);
// } catch (ArrayIndexOutOfBoundsException e) {
// send("Invalid command. " + e.getMessage(), outputStream);
// }
// }
//
//
// } catch (IOException e) {
// e.printStackTrace();
// }
// }
// }