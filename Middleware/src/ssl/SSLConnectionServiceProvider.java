package ssl;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPublicKeySpec;
import java.util.Arrays;

/**
 * TODO getjoepte shizzle vervangen
 * 
 * @author rhino
 *
 */
public class SSLConnectionServiceProvider extends Communicator {
	SSLSocketFactory sslSocketFactory;
	SSLSocket sslSocket;

	public SSLConnectionServiceProvider() {
		// System.setProperty("javax.net.ssl.keyStore", "ssl/Obama");
		// System.setProperty("javax.net.ssl.keyStorePassword", "ThankYou");
		System.setProperty("javax.net.ssl.trustStore", "ssl/client_truststore");
		System.setProperty("javax.net.ssl.trustStorePassword", "client_truststore");

		sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		sslSocket = null;
	}

	public byte[] fetchCert() {
		byte[] returnValue = null;
		try {
			sslSocket = (SSLSocket) sslSocketFactory.createSocket("localhost", 1338);
			sslSocket.startHandshake();

			InputStream inputStream = sslSocket.getInputStream();
			OutputStream outputStream = sslSocket.getOutputStream();

			send("0", outputStream);
			String cert = null;
			for (int i = 0; i < 9; i++) {
				cert += receive(inputStream);
			}

			cert = cert.split("null")[1];
			
			byte[] certInBytes = hexStringToByteArray(cert);

			System.out.println("Cert in hex: " + cert);
			System.out.println("Cert: " + Arrays.toString(certInBytes));

			inputStream.close();
			outputStream.close();

			returnValue = certInBytes;
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

	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

}