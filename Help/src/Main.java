import java.awt.Checkbox;
import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.xml.bind.DatatypeConverter;

import org.bouncycastle.openssl.PEMReader;

public class Main {
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
	private byte[] dummyPubExponent = new byte[] { (byte) 0x01, (byte) 0x00, (byte) 0x01 };
	private byte[] dummyPubModulus = new byte[] { (byte) 0x8d, (byte) 0x08, (byte) 0x00, (byte) 0x7e, (byte) 0x39,
			(byte) 0xb1, (byte) 0x52, (byte) 0x4e, (byte) 0xc8, (byte) 0x90, (byte) 0x90, (byte) 0x37, (byte) 0x93,
			(byte) 0xd1, (byte) 0xcc, (byte) 0x33, (byte) 0xa8, (byte) 0x8d, (byte) 0xd5, (byte) 0x88, (byte) 0x7d,
			(byte) 0x5c, (byte) 0xcc, (byte) 0x8a, (byte) 0x26, (byte) 0xaa, (byte) 0x05, (byte) 0x2d, (byte) 0x7c,
			(byte) 0xed, (byte) 0xd9, (byte) 0xc4, (byte) 0xec, (byte) 0x89, (byte) 0x4e, (byte) 0x27, (byte) 0x85,
			(byte) 0x9b, (byte) 0x33, (byte) 0x43, (byte) 0x72, (byte) 0xae, (byte) 0xe2, (byte) 0xc8, (byte) 0x4d,
			(byte) 0x7c, (byte) 0x04, (byte) 0x02, (byte) 0xcd, (byte) 0x46, (byte) 0xf0, (byte) 0x3b, (byte) 0xd8,
			(byte) 0xa0, (byte) 0xb9, (byte) 0xd1, (byte) 0x9d, (byte) 0x33, (byte) 0x44, (byte) 0xe1, (byte) 0xfa,
			(byte) 0x0d, (byte) 0xf6, (byte) 0x69 };

	public static void main(String[] args) {
		intToByteArray(1490635770);
		byte[] past = new byte[] { (byte) 88, (byte) -39, (byte) 74, (byte) -102 }; //Komt binnen
		byte[] future = new byte[] { (byte) 88, (byte) -39, (byte) 75, (byte) -6 }; //Staat op kaart
		System.out.println(checkIfPast(future, past));
//		byte[] test = { (byte) 1, (byte) 81, (byte) -128 };
		// System.out.println(fromByteArray(test).toString());

		// int unixTime = (int) (System.currentTimeMillis() / 1000);
		// byte[] bytes = intToByteArray(unixTime);
		// System.out.println(Arrays.toString(slice(bytes, (short) 2, (short)
		// 3)));

		// System.out.println(Arrays.toString(substractArray(intToByteArray(1489084085),
		// intToByteArray(1489076666))).toString());
		// System.out.println(fromByteArray(substractArray(intToByteArray(1489084085),
		// intToByteArray(1489076666))).toString());
		// int getal = 1489084085 - 1489076666;
		// System.out.println(getal);
		// intToByteArray(getal);

//		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
//		FileReader fr = null, fr2 = null;
//		try {
//			fr = new FileReader("../Certificaten2/g.crt");
//			fr2 = new FileReader("../Certificaten2/g.key");
//		} catch (FileNotFoundException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		PEMReader pemReader = new PEMReader(fr);
//		X509Certificate cert = null;
//		RSAPrivateKey sk = null;
//		RSAPublicKey pk = null;
//		try {
//			cert = (X509Certificate) pemReader.readObject();
//			pemReader = new PEMReader(fr2);
//			KeyPair kp = (KeyPair) pemReader.readObject();
//			sk = (RSAPrivateKey) kp.getPrivate();
//			pk = (RSAPublicKey) cert.getPublicKey();
//		} catch (IOException e) {
//			// TODO Auto-generated catch block
//			e.printStackTrace();
//		}
//		intToByteArray(pk.getModulus().intValue());
//		intToByteArray(pk.getPublicExponent().intValue());
//		toStringArray(pk.getEncoded());

		// byte[] digitalSignature = null;
		// try {
		// digitalSignature = signData(test, sk);
		// } catch (Exception e) {
		// // TODO Auto-generated catch block
		// e.printStackTrace();
		// }
		//
		// boolean verified = false;
		//
		// try {
		// verified = verifySig(test, pk, digitalSignature);
		// } catch (Exception e) {
		// // TODO Auto-generated catch block
		// e.printStackTrace();
		// }
		// System.out.println(verified) ;
	}
	
	private static boolean checkIfPast(byte[] lastTime, byte[] tempTimeUpdate) {
		// TODO: is het lastTime > tempTimeUpdate of is het lastTime <= tempTimeUpdate
		boolean past = false;
		for(short i = 0; i<4;i++){
			byte hulp = (byte) (lastTime[i] - tempTimeUpdate[i]);
			if(hulp > 0){
				past = true;
				break;
			}
		}
		return past;
	}

	private static void toStringArray(byte[] encoded) {
		StringBuilder sb = new StringBuilder();
		sb.append("{");
		for (int i = 0; i < encoded.length; i++) {
			sb.append("(byte) ");
			sb.append(encoded[i]);
			if (i != encoded.length - 1) {
				sb.append(",");
			}
		}
		sb.append("}");
		System.out.println(sb);
	}

	public static byte[] signData(byte[] data, PrivateKey key) throws Exception {
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initSign(key);
		signer.update(data);
		return (signer.sign());
	}

	public static boolean verifySig(byte[] data, PublicKey key, byte[] sig) throws Exception {
		Signature signer = Signature.getInstance("SHA1withRSA");
		signer.initVerify(key);
		signer.update(data);
		return (signer.verify(sig));

	}

	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

	private static byte[] substractArray(byte[] time, byte[] lastTime) {
		short length;
		if (time.length > lastTime.length) {
			length = (short) time.length;
		} else {
			length = (short) lastTime.length;
		}

		// Twee tijden van elkaar aftrekken
		byte[] result = new byte[length];
		for (int i = length - 1; i > -1; i--) {
			byte sub = (byte) (time[i] - lastTime[i]);
			result[i] = sub;
		}
		return result;
	}

	private static byte[] intToByteArray(final int i) {
		BigInteger bigInt = BigInteger.valueOf(i);
		String array = Arrays.toString(bigInt.toByteArray());
		array = array.replace(",", ", (byte)");
		array = array.replace("[", "[(byte) ");
		array = array.replace("[", "{ ");
		array = array.replace("]", " }");
		System.out.println(array);
		return bigInt.toByteArray();
	}

	private static BigInteger fromByteArray(byte[] bytes) {
		BigInteger n = new BigInteger(bytes);
		return n;
	}

	public static byte[] slice(byte[] original, short offset, short end) {
		byte[] slice = new byte[end - offset];
		for (short i = offset; i < end; i++) {
			short index = (short) (i - offset);
			slice[index] = original[i];
		}
		return slice;
	}
}
