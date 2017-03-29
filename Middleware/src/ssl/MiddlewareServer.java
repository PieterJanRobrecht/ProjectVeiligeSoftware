package ssl;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.security.cert.X509Certificate;

import controller.MiddlewareController;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;

/**
 * TODO evt nakijken of we dit niet kunnen gebruiken ipv public keys (dus die
 * certs):
 * http://stackoverflow.com/questions/36303236/verify-a-signature-in-java-using-openssl-generated-key-and-certificate
 * 
 * TODO vervang getjoepte exponenten/moduluss
 * 
 * @author rhino
 *
 */
public class MiddlewareServer extends Communicator implements Runnable {
	private MiddlewareController mc;
	private SSLServerSocketFactory sslServerSocketFactory;
	public MiddlewareServer(MiddlewareController mwc, SSLServerSocketFactory SSLServerSocketFactory) {
		this.mc = mwc;
		this.sslServerSocketFactory = SSLServerSocketFactory;
	}

	private byte[] intToByteArray(final int i) {
		BigInteger bigInt = BigInteger.valueOf(i);
		System.out.print("\tConverting " + i + " ...");
		System.out.println(" converted to " + Arrays.toString(bigInt.toByteArray()));
		return bigInt.toByteArray();
	}
	
	public static String bytesToHex(byte[] in) {
		final StringBuilder builder = new StringBuilder();
		for (byte b : in) {
			builder.append(String.format("%02x", b));
		}
		return builder.toString();
	}
	
	public byte[] generateSignatureForMessage(PrivateKey privKey, byte[]  message) throws Exception {
		Signature rsa = Signature.getInstance("SHA1withRSA");
		rsa.initSign(privKey);
		rsa.update(message);
		return rsa.sign();
	}

	public byte[] generateSignatureForMessage(RSAPrivateKey privKey, byte[] message) throws Exception {
		Signature rsa = Signature.getInstance("SHA1withRSA");
		rsa.initSign(privKey);
		rsa.update(message);
		return rsa.sign();
	}

	public static PrivateKey bigIntegerToPrivateKey(String mod, String exp) throws NoSuchAlgorithmException, InvalidKeySpecException {
		RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(new BigInteger(mod, 16), new BigInteger(exp, 16));
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PrivateKey privKey = fact.generatePrivate(keySpec);
		return privKey;
	}

	@Override
	public void run() {
//		System.setProperty("javax.net.ssl.keyStore", "ssl/server_keystore");
//		System.setProperty("javax.net.ssl.keyStorePassword", "server_keystore");
		System.setProperty("javax.net.ssl.trustStore", "ssl/server_truststore");
		System.setProperty("javax.net.ssl.trustStorePassword", "server_truststore");

		InputStream inputStream;
		OutputStream outputStream;
//
//		SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		SSLServerSocket sslServerSocket = null;

//		try {
//			sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(1345);
//		} catch (IOException e) {
//			System.err.println("Unable to initiate SSLServerSocket.");
//			e.printStackTrace();
//			System.exit(1);
//		}
//
//		while (true) {
//			try {
//				SSLSocket sslSocket = (SSLSocket) sslServerSocket.accept();
//				sslSocket.setNeedClientAuth(false);
//				SSLSession sslSession = sslSocket.getSession();
//				
//				inputStream = sslSocket.getInputStream();
//				outputStream = sslSocket.getOutputStream();
//
//				String[] message;
//				
//				while (true) {
//					message = receive(inputStream).split(" ");
//					try {
//						switch (Integer.parseInt(message[0])) {
//						case 0:
//							send("Kappa0", outputStream);
//							System.out.println("Fetching SP certificate and passing it to SC..");
//							mc.authenticateServiceProvider( /**
//															 * steek hier nog waarde in voor wie
//															 * willen we auth?
//															 **/
//							);
//							break;
//						case 1:
//							send("Kappa1", outputStream);
//							break;
//						case 2:
//							send("Kappa2", outputStream);
//							break;
//						case 3:
//							send("Kappa3", outputStream);
//							break;
//						default:
//							send("Invalid command.", outputStream);
//							break;
//						}
//					} catch (NumberFormatException e) {
//						send("Invalid command. " + e.getMessage(), outputStream);
//					} catch (ArrayIndexOutOfBoundsException e) {
//						send("Invalid command. " + e.getMessage(), outputStream);
//					} finally {
//						inputStream.close();
//						outputStream.close();
//					}
//				}
//					
//
//			} catch (IOException e) {
//				e.printStackTrace();
//			} catch (Exception e) {
//				e.printStackTrace();
//			}
//		}
	}
}