package ssl;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import com.sun.javafx.image.IntToBytePixelConverter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
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
public class SSLConnectionTimeServer extends Communicator {
	// getjoept.. moet nog aangepast worden aan eigen certificaten
	// gebruik momenteel overal dezelfde :')
	private byte[] dummyPrivExponent = new byte[] { (byte) 0x64, (byte) 0xc2, (byte) 0x8d, (byte) 0xcf, (byte) 0xa1, (byte) 0x1a, (byte) 0x7e, (byte) 0x6a, (byte) 0xc9, (byte) 0x42, (byte) 0xf7, (byte) 0xb6, (byte) 0xad, (byte) 0x86, (byte) 0xdb, (byte) 0xf5, (byte) 0x20, (byte) 0x7c, (byte) 0xcd, (byte) 0x4d, (byte) 0xe9, (byte) 0xfb, (byte) 0x2e, (byte) 0x2b, (byte) 0x99, (byte) 0xfa, (byte) 0x29, (byte) 0x1e, (byte) 0xd9, (byte) 0xbd, (byte) 0xf9, (byte) 0xb2, (byte) 0x77, (byte) 0x9e, (byte) 0x3e, (byte) 0x1a, (byte) 0x60, (byte) 0x67, (byte) 0x8e, (byte) 0xbd, (byte) 0xae, (byte) 0x36, (byte) 0x54, (byte) 0x4a, (byte) 0x11, (byte) 0xc2, (byte) 0x2e, (byte) 0x7c, (byte) 0x9e, (byte) 0xc3, (byte) 0xcb, (byte) 0xba, (byte) 0x65, (byte) 0x2b, (byte) 0xc5, (byte) 0x1b, (byte) 0x6f, (byte) 0x4f, (byte) 0x54, (byte) 0xe1, (byte) 0xff, (byte) 0xc3, (byte) 0x18, (byte) 0x81 };
	private byte[] dummyPrivModulus = new byte[] { (byte) 0x8d, (byte) 0x08, (byte) 0x00, (byte) 0x7e, (byte) 0x39, (byte) 0xb1, (byte) 0x52, (byte) 0x4e, (byte) 0xc8, (byte) 0x90, (byte) 0x90, (byte) 0x37, (byte) 0x93, (byte) 0xd1, (byte) 0xcc, (byte) 0x33, (byte) 0xa8, (byte) 0x8d, (byte) 0xd5, (byte) 0x88, (byte) 0x7d, (byte) 0x5c, (byte) 0xcc, (byte) 0x8a, (byte) 0x26, (byte) 0xaa, (byte) 0x05, (byte) 0x2d, (byte) 0x7c, (byte) 0xed, (byte) 0xd9, (byte) 0xc4, (byte) 0xec, (byte) 0x89, (byte) 0x4e, (byte) 0x27, (byte) 0x85, (byte) 0x9b, (byte) 0x33, (byte) 0x43, (byte) 0x72, (byte) 0xae, (byte) 0xe2, (byte) 0xc8, (byte) 0x4d, (byte) 0x7c, (byte) 0x04, (byte) 0x02, (byte) 0xcd, (byte) 0x46, (byte) 0xf0, (byte) 0x3b, (byte) 0xd8, (byte) 0xa0, (byte) 0xb9, (byte) 0xd1, (byte) 0x9d, (byte) 0x33, (byte) 0x44, (byte) 0xe1, (byte) 0xfa, (byte) 0x0d, (byte) 0xf6, (byte) 0x69 };
	private byte[] dummyPubExponent = new byte[] { (byte) 0x01, (byte) 0x00, (byte) 0x01 };
	private byte[] dummyPubModulus = new byte[] { (byte) 0x8d, (byte) 0x08, (byte) 0x00, (byte) 0x7e, (byte) 0x39, (byte) 0xb1, (byte) 0x52, (byte) 0x4e, (byte) 0xc8, (byte) 0x90, (byte) 0x90, (byte) 0x37, (byte) 0x93, (byte) 0xd1, (byte) 0xcc, (byte) 0x33, (byte) 0xa8, (byte) 0x8d, (byte) 0xd5, (byte) 0x88, (byte) 0x7d, (byte) 0x5c, (byte) 0xcc, (byte) 0x8a, (byte) 0x26, (byte) 0xaa, (byte) 0x05, (byte) 0x2d, (byte) 0x7c, (byte) 0xed, (byte) 0xd9, (byte) 0xc4, (byte) 0xec, (byte) 0x89, (byte) 0x4e, (byte) 0x27, (byte) 0x85, (byte) 0x9b, (byte) 0x33, (byte) 0x43, (byte) 0x72, (byte) 0xae, (byte) 0xe2, (byte) 0xc8, (byte) 0x4d, (byte) 0x7c, (byte) 0x04, (byte) 0x02, (byte) 0xcd, (byte) 0x46, (byte) 0xf0, (byte) 0x3b, (byte) 0xd8, (byte) 0xa0, (byte) 0xb9, (byte) 0xd1, (byte) 0x9d, (byte) 0x33, (byte) 0x44, (byte) 0xe1, (byte) 0xfa, (byte) 0x0d, (byte) 0xf6, (byte) 0x69 };

	private RSAPublicKey pubKey;
	
	private byte[] timeCert = new byte[] {(byte) 48,(byte) -126,(byte) 1,(byte) 126,(byte) 48,(byte) -126,(byte) 1,(byte) 40,(byte) 2,(byte) 1,(byte) 1,(byte) 48,(byte) 13,(byte) 6,(byte) 9,(byte) 42,(byte) -122,(byte) 72,(byte) -122,(byte) -9,(byte) 13,(byte) 1,(byte) 1,(byte) 11,(byte) 5,(byte) 0,(byte) 48,(byte) 72,(byte) 49,(byte) 11,(byte) 48,(byte) 9,(byte) 6,(byte) 3,(byte) 85,(byte) 4,(byte) 6,(byte) 19,(byte) 2,(byte) 66,(byte) 69,(byte) 49,(byte) 19,(byte) 48,(byte) 17,(byte) 6,(byte) 3,(byte) 85,(byte) 4,(byte) 8,(byte) 12,(byte) 10,(byte) 83,(byte) 111,(byte) 109,(byte) 101,(byte) 45,(byte) 83,(byte) 116,(byte) 97,(byte) 116,(byte) 101,(byte) 49,(byte) 17,(byte) 48,(byte) 15,(byte) 6,(byte) 3,(byte) 85,(byte) 4,(byte) 10,(byte) 12,(byte) 8,(byte) 67,(byte) 101,(byte) 114,(byte) 116,(byte) 65,(byte) 117,(byte) 116,(byte) 104,(byte) 49,(byte) 17,(byte) 48,(byte) 15,(byte) 6,(byte) 3,(byte) 85,(byte) 4,(byte) 3,(byte) 12,(byte) 8,(byte) 67,(byte) 101,(byte) 114,(byte) 116,(byte) 65,(byte) 117,(byte) 116,(byte) 104,(byte) 48,(byte) 30,(byte) 23,(byte) 13,(byte) 49,(byte) 55,(byte) 48,(byte) 51,(byte) 50,(byte) 55,(byte) 49,(byte) 49,(byte) 53,(byte) 48,(byte) 48,(byte) 52,(byte) 90,(byte) 23,(byte) 13,(byte) 49,(byte) 57,(byte) 48,(byte) 51,(byte) 50,(byte) 55,(byte) 49,(byte) 49,(byte) 53,(byte) 48,(byte) 48,(byte) 52,(byte) 90,(byte) 48,(byte) 76,(byte) 49,(byte) 11,(byte) 48,(byte) 9,(byte) 6,(byte) 3,(byte) 85,(byte) 4,(byte) 6,(byte) 19,(byte) 2,(byte) 66,(byte) 69,(byte) 49,(byte) 19,(byte) 48,(byte) 17,(byte) 6,(byte) 3,(byte) 85,(byte) 4,(byte) 8,(byte) 12,(byte) 10,(byte) 83,(byte) 111,(byte) 109,(byte) 101,(byte) 45,(byte) 83,(byte) 116,(byte) 97,(byte) 116,(byte) 101,(byte) 49,(byte) 19,(byte) 48,(byte) 17,(byte) 6,(byte) 3,(byte) 85,(byte) 4,(byte) 10,(byte) 12,(byte) 10,(byte) 84,(byte) 105,(byte) 109,(byte) 101,(byte) 83,(byte) 101,(byte) 114,(byte) 118,(byte) 101,(byte) 114,(byte) 49,(byte) 19,(byte) 48,(byte) 17,(byte) 6,(byte) 3,(byte) 85,(byte) 4,(byte) 3,(byte) 12,(byte) 10,(byte) 84,(byte) 105,(byte) 109,(byte) 101,(byte) 83,(byte) 101,(byte) 114,(byte) 118,(byte) 101,(byte) 114,(byte) 48,(byte) 92,(byte) 48,(byte) 13,(byte) 6,(byte) 9,(byte) 42,(byte) -122,(byte) 72,(byte) -122,(byte) -9,(byte) 13,(byte) 1,(byte) 1,(byte) 1,(byte) 5,(byte) 0,(byte) 3,(byte) 75,(byte) 0,(byte) 48,(byte) 72,(byte) 2,(byte) 65,(byte) 0,(byte) -17,(byte) -49,(byte) 3,(byte) -29,(byte) -86,(byte) 74,(byte) 61,(byte) -60,(byte) 101,(byte) -54,(byte) -76,(byte) 23,(byte) -75,(byte) 63,(byte) -88,(byte) 115,(byte) -93,(byte) -78,(byte) -22,(byte) -23,(byte) -74,(byte) 80,(byte) 73,(byte) -127,(byte) 89,(byte) -89,(byte) -77,(byte) -48,(byte) 8,(byte) 78,(byte) -104,(byte) 114,(byte) -65,(byte) -71,(byte) -117,(byte) -56,(byte) -126,(byte) 54,(byte) 69,(byte) -120,(byte) -75,(byte) 112,(byte) -35,(byte) 30,(byte) -71,(byte) -65,(byte) 98,(byte) 112,(byte) 107,(byte) 117,(byte) -10,(byte) 60,(byte) -44,(byte) -34,(byte) -119,(byte) 107,(byte) 74,(byte) 26,(byte) 74,(byte) 56,(byte) -43,(byte) -79,(byte) 113,(byte) 49,(byte) 2,(byte) 3,(byte) 1,(byte) 0,(byte) 1,(byte) 48,(byte) 13,(byte) 6,(byte) 9,(byte) 42,(byte) -122,(byte) 72,(byte) -122,(byte) -9,(byte) 13,(byte) 1,(byte) 1,(byte) 11,(byte) 5,(byte) 0,(byte) 3,(byte) 65,(byte) 0,(byte) 112,(byte) -111,(byte) 77,(byte) 12,(byte) -58,(byte) -66,(byte) 121,(byte) 125,(byte) -111,(byte) 87,(byte) -74,(byte) -102,(byte) 9,(byte) -56,(byte) 91,(byte) 62,(byte) -31,(byte) 78,(byte) 10,(byte) 37,(byte) -54,(byte) -108,(byte) 41,(byte) -81,(byte) -48,(byte) 78,(byte) -28,(byte) -87,(byte) -64,(byte) -105,(byte) -108,(byte) 108,(byte) 50,(byte) -11,(byte) 47,(byte) 71,(byte) 118,(byte) 19,(byte) -39,(byte) -12,(byte) 71,(byte) -108,(byte) 38,(byte) 28,(byte) -87,(byte) -50,(byte) -106,(byte) 55,(byte) 86,(byte) -6,(byte) -38,(byte) -42,(byte) -52,(byte) 61,(byte) 94,(byte) 16,(byte) 102,(byte) 0,(byte) -60,(byte) 9,(byte) 32,(byte) -122,(byte) -124,(byte) -28};
	private byte[] timePubExp = new byte[] { (byte) 1, (byte) 0, (byte) 1 };
	private byte[] timePubMod = new byte[] { (byte) -17, (byte) -49, (byte) 3, (byte) -29, (byte) -86, (byte) 74, (byte) 61, (byte) -60, (byte) 101, (byte) -54, (byte) -76, (byte) 23, (byte) -75, (byte) 63, (byte) -88, (byte) 115, (byte) -93, (byte) -78, (byte) -22, (byte) -23, (byte) -74, (byte) 80, (byte) 73, (byte) -127, (byte) 89, (byte) -89, (byte) -77, (byte) -48, (byte) 8, (byte) 78, (byte) -104, (byte) 114, (byte) -65, (byte) -71, (byte) -117, (byte) -56, (byte) -126, (byte) 54, (byte) 69, (byte) -120, (byte) -75, (byte) 112, (byte) -35, (byte) 30, (byte) -71, (byte) -65, (byte) 98, (byte) 112, (byte) 107, (byte) 117, (byte) -10, (byte) 60, (byte) -44, (byte) -34, (byte) -119, (byte) 107, (byte) 74, (byte) 26, (byte) 74, (byte) 56, (byte) -43, (byte) -79, (byte) 113, (byte) 49 };

	
	//private PublicKey timePubKey;
	
	SSLSocketFactory sslSocketFactory;
	SSLSocket sslSocket;

	public SSLConnectionTimeServer() {
		try {
//			String mod = bytesToHex(dummyPubModulus);
//			String exp = bytesToHex(dummyPubExponent);
//			pubKey = (RSAPublicKey) bigIntegerToPublicKey(mod, exp);
//			String mod = bytesToHex(timePubMod);
//			String exp = bytesToHex(timePubExp);
			pubKey = (RSAPublicKey) bigIntegerToPublicKey(timePubMod, timePubExp);
			
			CertificateFactory certFactory = CertificateFactory.getInstance("X.509");
			InputStream in = new ByteArrayInputStream(timeCert);
			X509Certificate cert = (X509Certificate)certFactory.generateCertificate(in);
			//timePubKey = cert.getPublicKey();
		} catch (NoSuchAlgorithmException e1) {
			e1.printStackTrace();
		} catch (InvalidKeySpecException e1) {
			e1.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		}

//		System.setProperty("javax.net.ssl.keyStore", "ssl/Obama");
//		System.setProperty("javax.net.ssl.keyStorePassword", "ThankYou");
		System.setProperty("javax.net.ssl.trustStore", "ssl/client_truststore");
		System.setProperty("javax.net.ssl.trustStorePassword", "client_truststore");

		sslSocketFactory = (SSLSocketFactory) SSLSocketFactory.getDefault();
		sslSocket = null;
	}

	public String[] fetchTime() {
		String[] returnValue = new String[2];
		try {
			sslSocket = (SSLSocket) sslSocketFactory.createSocket("localhost", 1336);
			sslSocket.startHandshake();

			InputStream inputStream = sslSocket.getInputStream();
			OutputStream outputStream = sslSocket.getOutputStream();

			String sig1 = receive(inputStream);
			String sig2 = receive(inputStream);
			String sig = sig1 + sig2;
			String time = receive(inputStream);
			System.out.println("Signature: " + sig);
			System.out.println("Signature in byte: " + Arrays.toString(hexStringToByteArray(sig)));
			System.out.println("Timestamp: " + time);

			System.out.println("Verified by MW: " + verifySignatureForMessage(pubKey, hexStringToByteArray(sig), time));
			inputStream.close();
			outputStream.close();

			returnValue[0] = sig;
			returnValue[1] = time;
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
	
	public boolean verifySignatureForMessage(PublicKey pubKey, byte[] sig, String message) throws Exception {
		Signature s = Signature.getInstance("SHA1withRSA");
		byte[] b = intToByteArray(Integer.parseInt(message));
		s.initVerify(pubKey);
		s.update(b);
		return s.verify(sig);
	}
	
	private byte[] intToByteArray(final int i) {
		BigInteger bigInt = BigInteger.valueOf(i);
		System.out.print("\tConverting " + i + " ...");
		System.out.println(" converted to " + Arrays.toString(bigInt.toByteArray()));
		return bigInt.toByteArray();
	}

//	public boolean verifySignatureForMessage(RSAPublicKey pubKey, byte[] sig, String message) throws Exception {
//		Signature s = Signature.getInstance("SHA1withRSA");
//		s.initVerify(pubKey);
//		s.update(message.getBytes());
//		return s.verify(sig);
//	}

	public static PublicKey bigIntegerToPublicKey(String mod, String exp) throws NoSuchAlgorithmException, InvalidKeySpecException {
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(new BigInteger(mod, 16), new BigInteger(exp, 16));
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PublicKey pubKey = fact.generatePublic(keySpec);
		return pubKey;
	}
	
	public static PublicKey bigIntegerToPublicKey(byte[] mod, byte[] exp) throws NoSuchAlgorithmException, InvalidKeySpecException {
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(new BigInteger(1, mod), new BigInteger(1, exp));
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PublicKey pubKey = fact.generatePublic(keySpec);
		return pubKey;
	}

	public static String bytesToHex(byte[] in) {
		final StringBuilder builder = new StringBuilder();
		for (byte b : in) {
			builder.append(String.format("%02x", b));
		}
		return builder.toString();
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