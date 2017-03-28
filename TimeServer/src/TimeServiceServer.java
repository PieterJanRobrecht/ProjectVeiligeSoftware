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
public class TimeServiceServer extends Communicator {
	// getjoept.. moet nog aangepast worden aan eigen certificaten
	// gebruik momenteel overal dezelfde :')
	private byte[] dummyPrivExponent = new byte[] { (byte) 0x64, (byte) 0xc2, (byte) 0x8d, (byte) 0xcf, (byte) 0xa1, (byte) 0x1a, (byte) 0x7e, (byte) 0x6a, (byte) 0xc9, (byte) 0x42, (byte) 0xf7, (byte) 0xb6, (byte) 0xad, (byte) 0x86, (byte) 0xdb, (byte) 0xf5, (byte) 0x20, (byte) 0x7c, (byte) 0xcd, (byte) 0x4d, (byte) 0xe9, (byte) 0xfb, (byte) 0x2e, (byte) 0x2b, (byte) 0x99, (byte) 0xfa, (byte) 0x29, (byte) 0x1e, (byte) 0xd9, (byte) 0xbd, (byte) 0xf9, (byte) 0xb2, (byte) 0x77, (byte) 0x9e, (byte) 0x3e, (byte) 0x1a, (byte) 0x60, (byte) 0x67, (byte) 0x8e, (byte) 0xbd, (byte) 0xae, (byte) 0x36, (byte) 0x54, (byte) 0x4a, (byte) 0x11, (byte) 0xc2, (byte) 0x2e, (byte) 0x7c, (byte) 0x9e, (byte) 0xc3, (byte) 0xcb, (byte) 0xba, (byte) 0x65, (byte) 0x2b, (byte) 0xc5, (byte) 0x1b, (byte) 0x6f, (byte) 0x4f, (byte) 0x54, (byte) 0xe1, (byte) 0xff, (byte) 0xc3, (byte) 0x18, (byte) 0x81 };
	private byte[] dummyPrivModulus = new byte[] { (byte) 0x8d, (byte) 0x08, (byte) 0x00, (byte) 0x7e, (byte) 0x39, (byte) 0xb1, (byte) 0x52, (byte) 0x4e, (byte) 0xc8, (byte) 0x90, (byte) 0x90, (byte) 0x37, (byte) 0x93, (byte) 0xd1, (byte) 0xcc, (byte) 0x33, (byte) 0xa8, (byte) 0x8d, (byte) 0xd5, (byte) 0x88, (byte) 0x7d, (byte) 0x5c, (byte) 0xcc, (byte) 0x8a, (byte) 0x26, (byte) 0xaa, (byte) 0x05, (byte) 0x2d, (byte) 0x7c, (byte) 0xed, (byte) 0xd9, (byte) 0xc4, (byte) 0xec, (byte) 0x89, (byte) 0x4e, (byte) 0x27, (byte) 0x85, (byte) 0x9b, (byte) 0x33, (byte) 0x43, (byte) 0x72, (byte) 0xae, (byte) 0xe2, (byte) 0xc8, (byte) 0x4d, (byte) 0x7c, (byte) 0x04, (byte) 0x02, (byte) 0xcd, (byte) 0x46, (byte) 0xf0, (byte) 0x3b, (byte) 0xd8, (byte) 0xa0, (byte) 0xb9, (byte) 0xd1, (byte) 0x9d, (byte) 0x33, (byte) 0x44, (byte) 0xe1, (byte) 0xfa, (byte) 0x0d, (byte) 0xf6, (byte) 0x69 };
	private byte[] dummyPubExponent = new byte[] { (byte) 0x01, (byte) 0x00, (byte) 0x01 };
	private byte[] dummyPubModulus = new byte[] { (byte) 0x8d, (byte) 0x08, (byte) 0x00, (byte) 0x7e, (byte) 0x39, (byte) 0xb1, (byte) 0x52, (byte) 0x4e, (byte) 0xc8, (byte) 0x90, (byte) 0x90, (byte) 0x37, (byte) 0x93, (byte) 0xd1, (byte) 0xcc, (byte) 0x33, (byte) 0xa8, (byte) 0x8d, (byte) 0xd5, (byte) 0x88, (byte) 0x7d, (byte) 0x5c, (byte) 0xcc, (byte) 0x8a, (byte) 0x26, (byte) 0xaa, (byte) 0x05, (byte) 0x2d, (byte) 0x7c, (byte) 0xed, (byte) 0xd9, (byte) 0xc4, (byte) 0xec, (byte) 0x89, (byte) 0x4e, (byte) 0x27, (byte) 0x85, (byte) 0x9b, (byte) 0x33, (byte) 0x43, (byte) 0x72, (byte) 0xae, (byte) 0xe2, (byte) 0xc8, (byte) 0x4d, (byte) 0x7c, (byte) 0x04, (byte) 0x02, (byte) 0xcd, (byte) 0x46, (byte) 0xf0, (byte) 0x3b, (byte) 0xd8, (byte) 0xa0, (byte) 0xb9, (byte) 0xd1, (byte) 0x9d, (byte) 0x33, (byte) 0x44, (byte) 0xe1, (byte) 0xfa, (byte) 0x0d, (byte) 0xf6, (byte) 0x69 };

	private RSAPrivateKey secretKey;

	private byte[] timeSecrKey = new byte[] { (byte) 48, (byte) -126, (byte) 1, (byte) 87, (byte) 2, (byte) 1, (byte) 0, (byte) 48, (byte) 13, (byte) 6, (byte) 9, (byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 1, (byte) 5, (byte) 0, (byte) 4, (byte) -126, (byte) 1, (byte) 65, (byte) 48, (byte) -126, (byte) 1, (byte) 61, (byte) 2, (byte) 1, (byte) 0, (byte) 2, (byte) 65, (byte) 0, (byte) -17, (byte) -49, (byte) 3, (byte) -29, (byte) -86, (byte) 74, (byte) 61, (byte) -60, (byte) 101, (byte) -54, (byte) -76, (byte) 23, (byte) -75, (byte) 63, (byte) -88, (byte) 115, (byte) -93, (byte) -78, (byte) -22, (byte) -23, (byte) -74, (byte) 80, (byte) 73, (byte) -127, (byte) 89, (byte) -89, (byte) -77, (byte) -48, (byte) 8, (byte) 78, (byte) -104, (byte) 114, (byte) -65, (byte) -71, (byte) -117, (byte) -56, (byte) -126, (byte) 54, (byte) 69, (byte) -120, (byte) -75, (byte) 112, (byte) -35, (byte) 30, (byte) -71, (byte) -65, (byte) 98, (byte) 112, (byte) 107, (byte) 117, (byte) -10, (byte) 60, (byte) -44, (byte) -34, (byte) -119, (byte) 107, (byte) 74, (byte) 26, (byte) 74, (byte) 56, (byte) -43, (byte) -79, (byte) 113, (byte) 49, (byte) 2, (byte) 3, (byte) 1, (byte) 0, (byte) 1, (byte) 2, (byte) 65, (byte) 0, (byte) -105, (byte) -124, (byte) 117, (byte) 48, (byte) -93, (byte) -89, (byte) -60, (byte) -33, (byte) 18, (byte) 113, (byte) -64, (byte) -40, (byte) 57, (byte) -20, (byte) -66, (byte) -62, (byte) 81, (byte) -21, (byte) -6, (byte) 1, (byte) 48, (byte) -16, (byte) 9, (byte) -127, (byte) 112, (byte) -28, (byte) 68, (byte) -8, (byte) 108, (byte) 71, (byte) 60, (byte) -118, (byte) 10, (byte) -27, (byte) -119, (byte) -102, (byte) -106, (byte) 111, (byte) 4, (byte) -99, (byte) -114, (byte) -101, (byte) -48, (byte) -68, (byte) -43, (byte) -43, (byte) 18, (byte) -113, (byte) -108, (byte) 80, (byte) 16, (byte) 24, (byte) -19, (byte) 64, (byte) 22, (byte) -75, (byte) -36, (byte) -44, (byte) -117, (byte) -4, (byte) 16, (byte) -88, (byte) 0, (byte) 1, (byte) 2, (byte) 33, (byte) 0, (byte) -2, (byte) 30, (byte) 23, (byte) -64, (byte) 34, (byte) -59, (byte) -82, (byte) 65, (byte) 3, (byte) 28, (byte) -11, (byte) 99, (byte) -102, (byte) -70, (byte) -78, (byte) 11, (byte) -39, (byte) 49, (byte) 94, (byte) -24, (byte) -70, (byte) 43, (byte) -49, (byte) 24, (byte) -28, (byte) -97, (byte) 25, (byte) -88, (byte) -52, (byte) 113, (byte) 0, (byte) 65, (byte) 2, (byte) 33, (byte) 0, (byte) -15, (byte) -107, (byte) -55, (byte) 127, (byte) 69, (byte) -87, (byte) 102, (byte) -120, (byte) -35, (byte) 25, (byte) -15, (byte) 120, (byte) 104, (byte) -27, (byte) -8, (byte) -8, (byte) 79, (byte) -2, (byte) -70, (byte) 74, (byte) 58, (byte) -105, (byte) -52, (byte) 48, (byte) 114, (byte) 20, (byte) 16, (byte) 3, (byte) -54, (byte) -125, (byte) 52, (byte) -15, (byte) 2, (byte) 33, (byte) 0, (byte) -79, (byte) -89, (byte) 102, (byte) 33, (byte) 75, (byte) -19, (byte) -7, (byte) -127, (byte) -73, (byte) -28, (byte) 113, (byte) -27, (byte) 125, (byte) -111, (byte) -47, (byte) -47, (byte) -104, (byte) -72, (byte) -4, (byte) 74, (byte) 37, (byte) -123, (byte) 101, (byte) 22, (byte) 89, (byte) 22, (byte) -91, (byte) -128, (byte) -83, (byte) -44, (byte) -66, (byte) 65, (byte) 2, (byte) 33, (byte) 0, (byte) -35, (byte) 53, (byte) 35, (byte) 104, (byte) -41, (byte) 119, (byte) -110, (byte) -68, (byte) -107, (byte) 127, (byte) -48, (byte) -36, (byte) 73, (byte) 104, (byte) -14, (byte) 125, (byte) 36, (byte) 122, (byte) -127, (byte) 71, (byte) -64, (byte) -71, (byte) 8, (byte) 45, (byte) -1, (byte) -9, (byte) 32, (byte) -26, (byte) -25, (byte) -61, (byte) 22, (byte) 113, (byte) 2, (byte) 33, (byte) 0, (byte) -6, (byte) 45, (byte) -3, (byte) 82, (byte) -83, (byte) -81, (byte) -59, (byte) 19, (byte) 104, (byte) 60, (byte) -42, (byte) -52, (byte) 22, (byte) 65, (byte) 4, (byte) -49, (byte) 117, (byte) 114, (byte) 35, (byte) -74, (byte) -105, (byte) -125, (byte) -98, (byte) 18, (byte) 97, (byte) -74, (byte) -67, (byte) 41, (byte) -104, (byte) 67, (byte) 40, (byte) 63 };
	private byte[] timeCert = new byte[] { (byte) 48, (byte) -126, (byte) 1, (byte) 126, (byte) 48, (byte) -126, (byte) 1, (byte) 40, (byte) 2, (byte) 1, (byte) 1, (byte) 48, (byte) 13, (byte) 6, (byte) 9, (byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 11, (byte) 5, (byte) 0, (byte) 48, (byte) 72, (byte) 49, (byte) 11, (byte) 48, (byte) 9, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 6, (byte) 19, (byte) 2, (byte) 66, (byte) 69, (byte) 49, (byte) 19, (byte) 48, (byte) 17, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 8, (byte) 12, (byte) 10, (byte) 83, (byte) 111, (byte) 109, (byte) 101, (byte) 45, (byte) 83, (byte) 116, (byte) 97, (byte) 116, (byte) 101, (byte) 49, (byte) 17, (byte) 48, (byte) 15, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 10, (byte) 12, (byte) 8, (byte) 67, (byte) 101, (byte) 114, (byte) 116, (byte) 65, (byte) 117, (byte) 116, (byte) 104, (byte) 49, (byte) 17, (byte) 48, (byte) 15, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 3, (byte) 12, (byte) 8, (byte) 67, (byte) 101, (byte) 114, (byte) 116, (byte) 65, (byte) 117, (byte) 116, (byte) 104, (byte) 48, (byte) 30, (byte) 23, (byte) 13, (byte) 49, (byte) 55, (byte) 48, (byte) 51, (byte) 50, (byte) 55, (byte) 49, (byte) 49, (byte) 53, (byte) 48, (byte) 48, (byte) 52, (byte) 90, (byte) 23, (byte) 13, (byte) 49, (byte) 57, (byte) 48, (byte) 51, (byte) 50, (byte) 55, (byte) 49, (byte) 49, (byte) 53, (byte) 48, (byte) 48, (byte) 52, (byte) 90, (byte) 48, (byte) 76, (byte) 49, (byte) 11, (byte) 48, (byte) 9, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 6, (byte) 19, (byte) 2, (byte) 66, (byte) 69, (byte) 49, (byte) 19, (byte) 48, (byte) 17, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 8, (byte) 12, (byte) 10, (byte) 83, (byte) 111, (byte) 109, (byte) 101, (byte) 45, (byte) 83, (byte) 116, (byte) 97, (byte) 116, (byte) 101, (byte) 49, (byte) 19, (byte) 48, (byte) 17, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 10, (byte) 12, (byte) 10, (byte) 84, (byte) 105, (byte) 109, (byte) 101, (byte) 83, (byte) 101, (byte) 114, (byte) 118, (byte) 101, (byte) 114, (byte) 49, (byte) 19, (byte) 48, (byte) 17, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 3, (byte) 12, (byte) 10, (byte) 84, (byte) 105, (byte) 109, (byte) 101, (byte) 83, (byte) 101, (byte) 114, (byte) 118, (byte) 101, (byte) 114, (byte) 48, (byte) 92, (byte) 48, (byte) 13, (byte) 6, (byte) 9, (byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 1, (byte) 5, (byte) 0, (byte) 3, (byte) 75, (byte) 0, (byte) 48, (byte) 72, (byte) 2, (byte) 65, (byte) 0, (byte) -17, (byte) -49, (byte) 3, (byte) -29, (byte) -86, (byte) 74, (byte) 61, (byte) -60, (byte) 101, (byte) -54, (byte) -76, (byte) 23, (byte) -75, (byte) 63, (byte) -88, (byte) 115, (byte) -93, (byte) -78, (byte) -22, (byte) -23, (byte) -74, (byte) 80, (byte) 73, (byte) -127, (byte) 89, (byte) -89, (byte) -77, (byte) -48, (byte) 8, (byte) 78, (byte) -104, (byte) 114, (byte) -65, (byte) -71, (byte) -117, (byte) -56, (byte) -126, (byte) 54, (byte) 69, (byte) -120, (byte) -75, (byte) 112, (byte) -35, (byte) 30, (byte) -71, (byte) -65, (byte) 98, (byte) 112, (byte) 107, (byte) 117, (byte) -10, (byte) 60, (byte) -44, (byte) -34, (byte) -119, (byte) 107, (byte) 74, (byte) 26, (byte) 74, (byte) 56, (byte) -43, (byte) -79, (byte) 113, (byte) 49, (byte) 2, (byte) 3, (byte) 1, (byte) 0, (byte) 1, (byte) 48, (byte) 13, (byte) 6, (byte) 9, (byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 11, (byte) 5, (byte) 0, (byte) 3, (byte) 65, (byte) 0, (byte) 112, (byte) -111, (byte) 77, (byte) 12, (byte) -58, (byte) -66, (byte) 121, (byte) 125, (byte) -111, (byte) 87, (byte) -74, (byte) -102, (byte) 9, (byte) -56, (byte) 91, (byte) 62, (byte) -31, (byte) 78, (byte) 10, (byte) 37, (byte) -54, (byte) -108, (byte) 41, (byte) -81, (byte) -48, (byte) 78, (byte) -28, (byte) -87, (byte) -64, (byte) -105, (byte) -108, (byte) 108, (byte) 50, (byte) -11, (byte) 47, (byte) 71, (byte) 118, (byte) 19, (byte) -39, (byte) -12, (byte) 71, (byte) -108, (byte) 38, (byte) 28, (byte) -87, (byte) -50, (byte) -106, (byte) 55, (byte) 86, (byte) -6, (byte) -38, (byte) -42, (byte) -52, (byte) 61, (byte) 94, (byte) 16, (byte) 102, (byte) 0, (byte) -60, (byte) 9, (byte) 32, (byte) -122, (byte) -124, (byte) -28 };

	private PrivateKey timeSecretKey;

	private TimeServiceServer() {

		/* Build private RSA Key */
		try {
			String mod = bytesToHex(dummyPrivModulus);
			String exp = bytesToHex(dummyPrivExponent);
			secretKey = (RSAPrivateKey) bigIntegerToPrivateKey(mod, exp);

			KeyFactory kf = KeyFactory.getInstance("RSA");
			timeSecretKey = kf.generatePrivate(new PKCS8EncodedKeySpec(timeSecrKey));
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

				String test = bytesToHex(generateSignatureForMessage(timeSecretKey, intToByteArray(unixTime)));
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

	public byte[] generateSignatureForMessage(PrivateKey privKey, byte[] message) throws Exception {
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

	public static void main(String[] args) {
		new TimeServiceServer();
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