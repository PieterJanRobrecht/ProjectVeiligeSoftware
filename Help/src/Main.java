import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;

import javax.xml.bind.DatatypeConverter;

public class Main {
	public static void main(String[] args) {
		// try {
		// String privKeyFile = "../test_key.pem";
		// PrivateKey key = null;
		// InputStream is = new ByteArrayInputStream( privKeyFile.getBytes() );;
		////
		//// is = privKeyFile.getClass().getResourceAsStream("/" + privKeyFile);
		// BufferedReader br = new BufferedReader(new InputStreamReader(is));
		// StringBuilder builder = new StringBuilder();
		// boolean inKey = false;
		// for (String line = br.readLine(); line != null; line = br.readLine())
		// {
		// if (!inKey) {
		// if (line.startsWith("-----BEGIN ") && line.endsWith(" PRIVATE
		// KEY-----")) {
		// inKey = true;
		// }
		// continue;
		// } else {
		// if (line.startsWith("-----END ") && line.endsWith(" PRIVATE
		// KEY-----")) {
		// inKey = false;
		// break;
		// }
		// builder.append(line);
		// }
		// }
		// //
		// byte[] encoded =
		// DatatypeConverter.parseBase64Binary(builder.toString());
		// PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
		// KeyFactory kf = KeyFactory.getInstance("RSA");
		// key = kf.generatePrivate(keySpec);
		// } catch (Exception e) {
		// e.printStackTrace();
		// }
		intToByteArray(86400);
		byte[] test = { (byte) 1, (byte) 81, (byte) -128 };
		System.out.println(fromByteArray(test));
	}

	private static void intToByteArray(final int i) {
		BigInteger bigInt = BigInteger.valueOf(i);
		String array = Arrays.toString(bigInt.toByteArray());
		array = array.replace(",", ", (byte)");
		array = array.replace("[", "[(byte) ");
		array = array.replace("[", "{ ");
		array = array.replace("]", " }");
		System.out.println(array);
	}

	private static String fromByteArray(byte[] bytes) {
		BigInteger n = new BigInteger(bytes);
		return n.toString();
	}
}
