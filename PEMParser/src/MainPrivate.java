import java.io.ByteArrayInputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

/**
 * TEST CLASS FOR INTERPRETATING .PEM FILES
 * 
 * TODO fix deze shizzle....? (rip private keys)
 * 
 * @author rhino
 *
 */
public class MainPrivate {
	public static void main(String[] args) {
		try {
			RSAPrivateKey privKey = getPrivateKey("C:\\Users\\rhino\\Documents\\GitHub\\ProjectVeiligeSoftware\\PEMParser\\files\\time_key.pem");
			System.out.println(privKey.toString());
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public static PrivateKey bigIntegerToPrivateKey(BigInteger e, BigInteger m) throws NoSuchAlgorithmException, InvalidKeySpecException {
		RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(m, e);
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PrivateKey privKey = fact.generatePrivate(keySpec);
		return privKey;
	}

	public static RSAPrivateKey getPrivateKey(String filename) throws Exception {
		File f = new File(filename);

		// read private key DER file
		DataInputStream dis = new DataInputStream(new FileInputStream(f));
		byte[] privKeyBytes = new byte[(int) f.length()];
		dis.read(privKeyBytes);
		dis.close();

		KeyFactory keyFactory = KeyFactory.getInstance("RSA");

		// decode private key
		PKCS8EncodedKeySpec privSpec = new PKCS8EncodedKeySpec(privKeyBytes);
		RSAPrivateKey privKey = (RSAPrivateKey) keyFactory.generatePrivate(privSpec);

		return privKey;
	}

}