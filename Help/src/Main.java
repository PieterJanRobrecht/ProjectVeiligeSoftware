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
//		intToByteArray(86400);
//		byte[] test = { (byte) 1, (byte) 81, (byte) -128 };
//		System.out.println(fromByteArray(test).toString());
		
//		int unixTime = (int) (System.currentTimeMillis() / 1000);
//		byte[] bytes = intToByteArray(unixTime);
//		System.out.println(Arrays.toString(slice(bytes, (short) 2, (short) 3)));
		
		System.out.println(Arrays.toString(substractArray(intToByteArray(1489084085), intToByteArray(1489076666))).toString());
		System.out.println(fromByteArray(substractArray(intToByteArray(1489084085), intToByteArray(1489076666))).toString());
		int getal = 1489084085 - 1489076666;
		System.out.println(getal);
		intToByteArray(getal);
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
		for (int i = length-1; i > -1; i--) {
			byte sub = (byte) (time[i] - lastTime[i] );
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
	
	public static byte[] slice(byte[] original, short offset, short end){
		byte[] slice = new byte[end - offset];
		for (short i = offset; i< end; i++){
			short index = (short) (i - offset);
			slice[index] = original[i];
		}
		return slice;
	}
}
