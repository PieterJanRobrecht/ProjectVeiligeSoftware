import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
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
import java.util.Base64;

public class MainPublic {
	public static void main(String[] args) {
		// TODO Auto-generated method stub
		CertificateFactory fact;
		try {
			fact = CertificateFactory.getInstance("X.509");
			FileInputStream is = new FileInputStream("C:\\Users\\rhino\\Documents\\GitHub\\ProjectVeiligeSoftware\\PEMParser\\files\\time_cert.pem");
			X509Certificate cer = (X509Certificate) fact.generateCertificate(is);

			RSAPublicKey key = (RSAPublicKey) cer.getPublicKey();
			System.out.println(key.toString());

			byte[] array = key.getModulus().toByteArray();
			if (array[0] == 0) {
			    byte[] tmp = new byte[array.length - 1];
			    System.arraycopy(array, 1, tmp, 0, tmp.length);
			    array = tmp;
			}
			
			System.out.print("\n\nModulus in byte[]: \nnew byte[] { ");
			for (byte b : array) {
				System.out.print("(byte) " + b + ", ");
			}
			System.out.println("};");
			System.out.println("Vergeert , opt einde ni weg te doen!!");
			

			array = key.getPublicExponent().toByteArray();
			if (array[0] == 0) {
			    byte[] tmp = new byte[array.length - 1];
			    System.arraycopy(array, 1, tmp, 0, tmp.length);
			    array = tmp;
			}
			
			System.out.print("\n\nModulus in byte[]: \nnew byte[] { ");
			for (byte b : array) {
				System.out.print("(byte) " + b + ", ");
			}
			System.out.println("};");
			System.out.println("Vergeert , opt einde ni weg te doen!!");
			
			System.out.print("\n\nEncoded public key in byte[]: \nnew byte[] { ");
			// new byte[] { (byte) -116, (byte) 31, ..., (byte) 54 };
			for (byte b : key.getEncoded()) {
				System.out.print("(byte) " + b + ", ");
			}
			System.out.println("};");
			System.out.println("Vergeert , opt einde ni weg te doen!!");

		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
	public static PublicKey bigIntegerToPublicKey(BigInteger e, BigInteger m) throws NoSuchAlgorithmException, InvalidKeySpecException  {
	    RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
	    KeyFactory fact = KeyFactory.getInstance("RSA");
	    PublicKey pubKey = fact.generatePublic(keySpec);
	    return pubKey;
	}
}
