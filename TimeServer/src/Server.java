import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.security.cert.X509Certificate;

import java.io.*;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
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
public class Server extends Communicator {
	// getjoept.. moet nog aangepast worden aan eigen certificaten
	// gebruik momenteel overal dezelfde :')
	private byte[] dummyPrivExponent = new byte[] { (byte) 0x64, (byte) 0xc2, (byte) 0x8d, (byte) 0xcf, (byte) 0xa1, (byte) 0x1a, (byte) 0x7e, (byte) 0x6a, (byte) 0xc9, (byte) 0x42, (byte) 0xf7, (byte) 0xb6, (byte) 0xad, (byte) 0x86, (byte) 0xdb, (byte) 0xf5, (byte) 0x20, (byte) 0x7c, (byte) 0xcd, (byte) 0x4d, (byte) 0xe9, (byte) 0xfb, (byte) 0x2e, (byte) 0x2b, (byte) 0x99, (byte) 0xfa, (byte) 0x29, (byte) 0x1e, (byte) 0xd9, (byte) 0xbd, (byte) 0xf9, (byte) 0xb2, (byte) 0x77, (byte) 0x9e, (byte) 0x3e, (byte) 0x1a, (byte) 0x60, (byte) 0x67, (byte) 0x8e, (byte) 0xbd, (byte) 0xae, (byte) 0x36, (byte) 0x54, (byte) 0x4a, (byte) 0x11, (byte) 0xc2, (byte) 0x2e, (byte) 0x7c, (byte) 0x9e, (byte) 0xc3, (byte) 0xcb, (byte) 0xba, (byte) 0x65, (byte) 0x2b, (byte) 0xc5, (byte) 0x1b, (byte) 0x6f, (byte) 0x4f, (byte) 0x54, (byte) 0xe1, (byte) 0xff, (byte) 0xc3, (byte) 0x18, (byte) 0x81 };
	private byte[] dummyPrivModulus = new byte[] { (byte) 0x8d, (byte) 0x08, (byte) 0x00, (byte) 0x7e, (byte) 0x39, (byte) 0xb1, (byte) 0x52, (byte) 0x4e, (byte) 0xc8, (byte) 0x90, (byte) 0x90, (byte) 0x37, (byte) 0x93, (byte) 0xd1, (byte) 0xcc, (byte) 0x33, (byte) 0xa8, (byte) 0x8d, (byte) 0xd5, (byte) 0x88, (byte) 0x7d, (byte) 0x5c, (byte) 0xcc, (byte) 0x8a, (byte) 0x26, (byte) 0xaa, (byte) 0x05, (byte) 0x2d, (byte) 0x7c, (byte) 0xed, (byte) 0xd9, (byte) 0xc4, (byte) 0xec, (byte) 0x89, (byte) 0x4e, (byte) 0x27, (byte) 0x85, (byte) 0x9b, (byte) 0x33, (byte) 0x43, (byte) 0x72, (byte) 0xae, (byte) 0xe2, (byte) 0xc8, (byte) 0x4d, (byte) 0x7c, (byte) 0x04, (byte) 0x02, (byte) 0xcd, (byte) 0x46, (byte) 0xf0, (byte) 0x3b, (byte) 0xd8, (byte) 0xa0, (byte) 0xb9, (byte) 0xd1, (byte) 0x9d, (byte) 0x33, (byte) 0x44, (byte) 0xe1, (byte) 0xfa, (byte) 0x0d, (byte) 0xf6, (byte) 0x69 };
	private byte[] dummyPubExponent = new byte[] { (byte) 0x01, (byte) 0x00, (byte) 0x01 };
	private byte[] dummyPubModulus = new byte[] { (byte) 0x8d, (byte) 0x08, (byte) 0x00, (byte) 0x7e, (byte) 0x39, (byte) 0xb1, (byte) 0x52, (byte) 0x4e, (byte) 0xc8, (byte) 0x90, (byte) 0x90, (byte) 0x37, (byte) 0x93, (byte) 0xd1, (byte) 0xcc, (byte) 0x33, (byte) 0xa8, (byte) 0x8d, (byte) 0xd5, (byte) 0x88, (byte) 0x7d, (byte) 0x5c, (byte) 0xcc, (byte) 0x8a, (byte) 0x26, (byte) 0xaa, (byte) 0x05, (byte) 0x2d, (byte) 0x7c, (byte) 0xed, (byte) 0xd9, (byte) 0xc4, (byte) 0xec, (byte) 0x89, (byte) 0x4e, (byte) 0x27, (byte) 0x85, (byte) 0x9b, (byte) 0x33, (byte) 0x43, (byte) 0x72, (byte) 0xae, (byte) 0xe2, (byte) 0xc8, (byte) 0x4d, (byte) 0x7c, (byte) 0x04, (byte) 0x02, (byte) 0xcd, (byte) 0x46, (byte) 0xf0, (byte) 0x3b, (byte) 0xd8, (byte) 0xa0, (byte) 0xb9, (byte) 0xd1, (byte) 0x9d, (byte) 0x33, (byte) 0x44, (byte) 0xe1, (byte) 0xfa, (byte) 0x0d, (byte) 0xf6, (byte) 0x69 };

	private RSAPrivateKey secretKey;

	private Server() {

		/* Build private RSA Key */
		try {
			String mod = bytesToHex(dummyPrivModulus);
			String exp = bytesToHex(dummyPrivExponent);
			secretKey = (RSAPrivateKey) bigIntegerToPrivateKey(mod, exp);

		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (InvalidKeySpecException e1) {
			e1.printStackTrace();
		}

		System.setProperty("javax.net.ssl.keyStore", "ssl/server_keystore");
		System.setProperty("javax.net.ssl.keyStorePassword", "server_keystore");
		System.setProperty("javax.net.ssl.trustStore", "ssl/server_truststore");
		System.setProperty("javax.net.ssl.trustStorePassword", "server_truststore");

		InputStream inputStream;
		OutputStream outputStream;

		SSLServerSocketFactory sslServerSocketFactory = (SSLServerSocketFactory) SSLServerSocketFactory.getDefault();
		SSLServerSocket sslServerSocket = null;

		try {
			sslServerSocket = (SSLServerSocket) sslServerSocketFactory.createServerSocket(1336);
		} catch (IOException e) {
			System.err.println("Unable to initiate SSLServerSocket.");
			e.printStackTrace();
			System.exit(1);
		}

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

				inputStream = sslSocket.getInputStream();
				outputStream = sslSocket.getOutputStream();

				int unixTime = (int) (System.currentTimeMillis() / 1000);

				System.out.println("Client connected to fetch time, returning " + unixTime);

				String test = bytesToHex(generateSignatureForMessage(secretKey, "" + unixTime));
				send(test.substring(0, 80), outputStream);
				send(test.substring(80, 128), outputStream);
				send("" + unixTime, outputStream);

				inputStream.close();
				outputStream.close();

			} catch (IOException e) {
				e.printStackTrace();
			} catch (Exception e) {
				e.printStackTrace();
			}
		}
	}

	public static String bytesToHex(byte[] in) {
		final StringBuilder builder = new StringBuilder();
		for (byte b : in) {
			builder.append(String.format("%02x", b));
		}
		return builder.toString();
	}

	public byte[] generateSignatureForMessage(RSAPrivateKey privKey, String message) throws Exception {
		Signature rsa = Signature.getInstance("SHA1withRSA");
		rsa.initSign(privKey);
		rsa.update(message.getBytes());
		return rsa.sign();
	}

	public static PrivateKey bigIntegerToPrivateKey(String mod, String exp) throws NoSuchAlgorithmException, InvalidKeySpecException {
		RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(new BigInteger(mod, 16), new BigInteger(exp, 16));
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PrivateKey privKey = fact.generatePrivate(keySpec);
		return privKey;
	}

	public static void main(String[] args) {
		new Server();
	}

	// /**
	// * DEBUG --> komt overeen met bovenstaand gegenereerde exponent/modulus
	// **/
	//
	// byte[] array = secretKey.getModulus().toByteArray();
	// if (array[0] == 0) {
	// byte[] tmp = new byte[array.length - 1];
	// System.arraycopy(array, 1, tmp, 0, tmp.length);
	// array = tmp;
	// }
	//
	// System.out.print("Modulus in byte[]: \nnew byte[] { ");
	// for (byte b : array) {
	// System.out.print("(byte) " + b + ", ");
	// }
	// System.out.println("};");
	// System.out.println("Vergeert , opt einde ni weg te doen!!");
	//
	// array = secretKey.getPrivateExponent().toByteArray();
	// if (array[0] == 0) {
	// byte[] tmp = new byte[array.length - 1];
	// System.arraycopy(array, 1, tmp, 0, tmp.length);
	// array = tmp;
	// }
	// System.out.print("\n\nModulus in byte[]: \nnew byte[] { ");
	// for (byte b : array) {
	// System.out.print("(byte) " + b + ", ");
	// }
	// System.out.println("};");
}