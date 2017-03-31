import java.awt.image.BufferedImage;
import java.awt.image.DataBufferByte;
import java.awt.image.WritableRaster;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
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

import javax.imageio.ImageIO;

/**
 * TEST CLASS FOR INTERPRETATING .PEM FILES
 * 
 * @author rhino
 *
 */
public class MainPublic {
	public static void main(String[] args) {

		String naam = "KappaKoning";
		String adres = "Gebroedersdesmet straat 1";
		String land = "Belgie";
		String geboorteDatum = "20/01/2017";
		String leeftijd = "17";
		String geslacht = "DidYouJustAssumeMyGender";

		byte[] foto = null;
		try {
			foto = extractBytes("C:\\Users\\rhino\\Documents\\download.jpg");
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		System.out.print("Naam: \n byte[] naam = new byte[] { ");
		for(byte b : naam.getBytes()) {
			System.out.print("(byte) " + b + ", ");
		}
		System.out.println("};");


		System.out.print("Adres: \n byte[] adres = new byte[] { ");
		for(byte b : adres.getBytes()) {
			System.out.print("(byte) " + b + ", ");
		}
		System.out.println("};");

		

		System.out.print("Land: \n byte[] land = new byte[] { ");
		for(byte b : land.getBytes()) {
			System.out.print("(byte) " + b + ", ");
		}
		System.out.println("};");

		

		System.out.print("Geboorte datum: \n byte[] geboorteDatum = new byte[] { ");
		for(byte b : geboorteDatum.getBytes()) {
			System.out.print("(byte) " + b + ", ");
		}
		System.out.println("};");

		

		System.out.print("Leeftijd: \n byte[] leeftijd = new byte[] { ");
		for(byte b : leeftijd.getBytes()) {
			System.out.print("(byte) " + b + ", ");
		}
		System.out.println("};");

		

		System.out.print("Geslacht: \n byte[] geslacht = new byte[] { ");
		for(byte b : geslacht.getBytes()) {
			System.out.print("(byte) " + b + ", ");
		}
		System.out.println("};");

		

		System.out.print("Foto: \n byte[] foto = new byte[] { ");
		for(byte b : foto) {
			System.out.print("(byte) " + b + ", ");
		}
		System.out.println("};");

		// CertificateFactory fact;
		// try {
		// fact = CertificateFactory.getInstance("X.509");
		// FileInputStream is = new
		// FileInputStream("C:\\Users\\rhino\\Documents\\GitHub\\ProjectVeiligeSoftware\\PEMParser\\files\\time_cert.pem");
		// X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
		//
		// RSAPublicKey key = (RSAPublicKey) cer.getPublicKey();
		// System.out.println(key.toString());
		//
		// byte[] array = key.getModulus().toByteArray();
		// if (array[0] == 0) {
		// byte[] tmp = new byte[array.length - 1];
		// System.arraycopy(array, 1, tmp, 0, tmp.length);
		// array = tmp;
		// }
		//
		// System.out.print("\n\nModulus in byte[]: \nnew byte[] { ");
		// for (byte b : array) {
		// System.out.print("(byte) " + b + ", ");
		// }
		// System.out.println("};");
		// System.out.println("Vergeert , opt einde ni weg te doen!!");
		//
		// array = key.getPublicExponent().toByteArray();
		// if (array[0] == 0) {
		// byte[] tmp = new byte[array.length - 1];
		// System.arraycopy(array, 1, tmp, 0, tmp.length);
		// array = tmp;
		// }
		//
		// System.out.print("\n\nModulus in byte[]: \nnew byte[] { ");
		// for (byte b : array) {
		// System.out.print("(byte) " + b + ", ");
		// }
		// System.out.println("};");
		// System.out.println("Vergeert , opt einde ni weg te doen!!");
		//
		// System.out.print("\n\nEncoded public key in byte[]: \nnew byte[] {
		// ");
		// // new byte[] { (byte) -116, (byte) 31, ..., (byte) 54 };
		// for (byte b : key.getEncoded()) {
		// System.out.print("(byte) " + b + ", ");
		// }
		// System.out.println("};");
		// System.out.println("Vergeert , opt einde ni weg te doen!!");
		//
		// } catch (CertificateException e) {
		// e.printStackTrace();
		// } catch (FileNotFoundException e) {
		// e.printStackTrace();
		// }
	}

	public static byte[] extractBytes(String ImageName) throws IOException {
		// open image
		File imgPath = new File(ImageName);
		BufferedImage bufferedImage = ImageIO.read(imgPath);

		// get DataBufferBytes from Raster
		WritableRaster raster = bufferedImage.getRaster();
		DataBufferByte data = (DataBufferByte) raster.getDataBuffer();

		return (data.getData());
	}

	public static PublicKey bigIntegerToPublicKey(BigInteger e, BigInteger m) throws NoSuchAlgorithmException, InvalidKeySpecException {
		RSAPublicKeySpec keySpec = new RSAPublicKeySpec(m, e);
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PublicKey pubKey = fact.generatePublic(keySpec);
		return pubKey;
	}
}
