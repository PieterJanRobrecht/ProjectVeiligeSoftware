package be.msec.client;

import be.msec.client.connection.Connection;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;
import controller.MiddlewareController;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import javax.smartcardio.*;

public class Client extends Application{

	private final static byte IDENTITY_CARD_CLA = (byte) 0x80;
	private static final byte VALIDATE_PIN_INS = 0x22;
	private static final byte GET_IDENTITY_INS = 0x26;
	private static final byte GET_NAME_INS = 0x24;
	private static final byte SIGN_INS = 0x28;
	private static final byte ASK_LENGTH_INS = 0x30;
	private static final byte GET_CERT_INS = 0x32;
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

	private static byte[] certificate = new byte[] { (byte) 48, (byte) -126, (byte) 1, (byte) -67, (byte) 48,
			(byte) -126, (byte) 1, (byte) 103, (byte) -96, (byte) 3, (byte) 2, (byte) 1, (byte) 2, (byte) 2, (byte) 5,
			(byte) 0, (byte) -73, (byte) -43, (byte) 96, (byte) -107, (byte) 48, (byte) 13, (byte) 6, (byte) 9,
			(byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 5,
			(byte) 5, (byte) 0, (byte) 48, (byte) 100, (byte) 49, (byte) 11, (byte) 48, (byte) 9, (byte) 6, (byte) 3,
			(byte) 85, (byte) 4, (byte) 6, (byte) 19, (byte) 2, (byte) 66, (byte) 69, (byte) 49, (byte) 13, (byte) 48,
			(byte) 11, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 7, (byte) 12, (byte) 4, (byte) 71, (byte) 101,
			(byte) 110, (byte) 116, (byte) 49, (byte) 25, (byte) 48, (byte) 23, (byte) 6, (byte) 3, (byte) 85, (byte) 4,
			(byte) 10, (byte) 12, (byte) 16, (byte) 75, (byte) 97, (byte) 72, (byte) 111, (byte) 32, (byte) 83,
			(byte) 105, (byte) 110, (byte) 116, (byte) 45, (byte) 76, (byte) 105, (byte) 101, (byte) 118, (byte) 101,
			(byte) 110, (byte) 49, (byte) 20, (byte) 48, (byte) 18, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 11,
			(byte) 12, (byte) 11, (byte) 86, (byte) 97, (byte) 107, (byte) 103, (byte) 114, (byte) 111, (byte) 101,
			(byte) 112, (byte) 32, (byte) 73, (byte) 84, (byte) 49, (byte) 21, (byte) 48, (byte) 19, (byte) 6, (byte) 3,
			(byte) 85, (byte) 4, (byte) 3, (byte) 12, (byte) 12, (byte) 74, (byte) 97, (byte) 110, (byte) 32, (byte) 86,
			(byte) 111, (byte) 115, (byte) 115, (byte) 97, (byte) 101, (byte) 114, (byte) 116, (byte) 48, (byte) 32,
			(byte) 23, (byte) 13, (byte) 49, (byte) 48, (byte) 48, (byte) 50, (byte) 50, (byte) 52, (byte) 48,
			(byte) 57, (byte) 52, (byte) 51, (byte) 48, (byte) 50, (byte) 90, (byte) 24, (byte) 15, (byte) 53,
			(byte) 49, (byte) 55, (byte) 57, (byte) 48, (byte) 49, (byte) 48, (byte) 57, (byte) 49, (byte) 57,
			(byte) 50, (byte) 57, (byte) 52, (byte) 50, (byte) 90, (byte) 48, (byte) 100, (byte) 49, (byte) 11,
			(byte) 48, (byte) 9, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 6, (byte) 19, (byte) 2, (byte) 66,
			(byte) 69, (byte) 49, (byte) 13, (byte) 48, (byte) 11, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 7,
			(byte) 12, (byte) 4, (byte) 71, (byte) 101, (byte) 110, (byte) 116, (byte) 49, (byte) 25, (byte) 48,
			(byte) 23, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 10, (byte) 12, (byte) 16, (byte) 75, (byte) 97,
			(byte) 72, (byte) 111, (byte) 32, (byte) 83, (byte) 105, (byte) 110, (byte) 116, (byte) 45, (byte) 76,
			(byte) 105, (byte) 101, (byte) 118, (byte) 101, (byte) 110, (byte) 49, (byte) 20, (byte) 48, (byte) 18,
			(byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 11, (byte) 12, (byte) 11, (byte) 86, (byte) 97, (byte) 107,
			(byte) 103, (byte) 114, (byte) 111, (byte) 101, (byte) 112, (byte) 32, (byte) 73, (byte) 84, (byte) 49,
			(byte) 21, (byte) 48, (byte) 19, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 3, (byte) 12, (byte) 12,
			(byte) 74, (byte) 97, (byte) 110, (byte) 32, (byte) 86, (byte) 111, (byte) 115, (byte) 115, (byte) 97,
			(byte) 101, (byte) 114, (byte) 116, (byte) 48, (byte) 92, (byte) 48, (byte) 13, (byte) 6, (byte) 9,
			(byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 1,
			(byte) 5, (byte) 0, (byte) 3, (byte) 75, (byte) 0, (byte) 48, (byte) 72, (byte) 2, (byte) 65, (byte) 0,
			(byte) -73, (byte) -43, (byte) 96, (byte) -107, (byte) 82, (byte) 25, (byte) -66, (byte) 34, (byte) 5,
			(byte) -58, (byte) 75, (byte) -39, (byte) -54, (byte) 43, (byte) 25, (byte) -117, (byte) 80, (byte) -62,
			(byte) 51, (byte) 19, (byte) 59, (byte) -70, (byte) -100, (byte) 85, (byte) 24, (byte) -57, (byte) 108,
			(byte) -98, (byte) -2, (byte) 1, (byte) -80, (byte) -39, (byte) 63, (byte) 93, (byte) 112, (byte) 7,
			(byte) 4, (byte) 18, (byte) -11, (byte) -98, (byte) 17, (byte) 126, (byte) -54, (byte) 27, (byte) -56,
			(byte) 33, (byte) 77, (byte) -111, (byte) -74, (byte) -78, (byte) 88, (byte) 70, (byte) -22, (byte) -3,
			(byte) 15, (byte) 16, (byte) 37, (byte) -18, (byte) 92, (byte) 74, (byte) 124, (byte) -107, (byte) -116,
			(byte) -125, (byte) 2, (byte) 3, (byte) 1, (byte) 0, (byte) 1, (byte) 48, (byte) 13, (byte) 6, (byte) 9,
			(byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 5,
			(byte) 5, (byte) 0, (byte) 3, (byte) 65, (byte) 0, (byte) 33, (byte) 97, (byte) 121, (byte) -25, (byte) 43,
			(byte) -47, (byte) 113, (byte) -104, (byte) -11, (byte) -42, (byte) -46, (byte) -17, (byte) 1, (byte) -38,
			(byte) 50, (byte) 59, (byte) -63, (byte) -74, (byte) -33, (byte) 90, (byte) 92, (byte) -59, (byte) 99,
			(byte) -17, (byte) -60, (byte) 17, (byte) 25, (byte) 79, (byte) 68, (byte) 68, (byte) -57, (byte) -8,
			(byte) -64, (byte) 35, (byte) -19, (byte) -114, (byte) 110, (byte) -116, (byte) 31, (byte) -126, (byte) -24,
			(byte) 54, (byte) 71, (byte) 82, (byte) -53, (byte) -78, (byte) -84, (byte) -45, (byte) -83, (byte) 87,
			(byte) 68, (byte) 124, (byte) -1, (byte) -128, (byte) -49, (byte) 124, (byte) 103, (byte) 28, (byte) 56,
			(byte) -114, (byte) -10, (byte) 97, (byte) -78, (byte) 54 };

	public void start(Stage primaryStage) {
		try {
			// Laden van de fxml file waarin alle gui elementen zitten
			FXMLLoader loader = new FXMLLoader();
			Parent root = FXMLLoader.load(getClass().getResource("../../../MiddlewareGui.fxml"));

			// Setten van enkele elementen van het hoofdscherm
			primaryStage.setTitle("Login Screen");
			primaryStage.setScene(new Scene(root));
			primaryStage.show();

			// Ophalen van de controller horende bij de view klasse
			MiddlewareController middlewareController = loader.<MiddlewareController>getController();
			assert (middlewareController != null);			
			
		} catch (IOException e) {
			e.printStackTrace();
		}
	}
	
	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		launch(args);

//		try {
//
//			/*
//			 * For more info on the use of CommandAPDU and ResponseAPDU: See
//			 * http://java.sun.com/javase/6/docs/jre/api/security/smartcardio/
//			 * spec/index.html
//			 */
//
//			CommandAPDU a;
//			ResponseAPDU r;
//
//			boolean simulator = false;
////
////			// 0. create applet (only for simulator!!!)
////			a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,
////					new byte[] { (byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08, 0x01 }, 0x7f);
////			r = c.transmit(a);
////			System.out.println(r);
////			if (r.getSW() != 0x9000)
////				throw new Exception("select installer applet failed");
////
////			a = new CommandAPDU(0x80, 0xB8, 0x00, 0x00,
////					new byte[] { 0xb, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00 }, 0x7f);
////			r = c.transmit(a);
////			System.out.println(r);
////			if (r.getSW() != 0x9000)
////				throw new Exception("Applet creation failed");
////
////			// 1. Select applet (not required on a real card, applet is selected
////			// by default)
////			a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,
////					new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00 }, 0x7f);
////			r = c.transmit(a);
////			System.out.println(r);
////			if (r.getSW() != 0x9000)
////				throw new Exception("Applet selection failed");
//
//			// 2. Send PIN
//			a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00, new byte[] { 0x01, 0x02, 0x03, 0x04 });
//			r = c.transmit(a);
//
//			System.out.println(r);
//			if (r.getSW() == SW_VERIFICATION_FAILED)
//				throw new Exception("PIN INVALID");
//			else if (r.getSW() != 0x9000)
//				throw new Exception("Exception on the card: " + r.getSW());
//			System.out.println("PIN Verified");
//
//			// 3. Get identity instruction
//			a = new CommandAPDU(IDENTITY_CARD_CLA, GET_IDENTITY_INS, 0x00, 0x00, 0xff);
//			r = c.transmit(a);
//
//			System.out.println(r);
//			if (r.getSW() != 0x9000)
//				throw new Exception("Exception on the card: " + r.getSW());
//
//			byte[] inc = r.getData();
//
//			System.out.println(new BigInteger(1, inc).toString(16));
//
//			if (simulator) {
//				System.out.println("Na filter.. \n" + new BigInteger(1, filterSimulator(inc, a)).toString(16));
//			}
//
//			/**
//			 * 8024000000374a616e20566f737361657274200a416674616e736520737465656e7765672033200a39303030200a47656e74200a6d616e200a31393837)
//			 * die 80 24 000 000 komt van 0x80 (CLA), 0x24 (INS) en dan die 2x
//			 * 000 door 0x00 (p1 en p2) wat volgt is dan die ins_file uit
//			 * IDcard.java
//			 * 
//			 * ^enkel op simulator ;-;
//			 */
//
//			// 4. get name instruction
//			a = new CommandAPDU(IDENTITY_CARD_CLA, GET_NAME_INS, 0x00, 0x00, 0xff);
//			r = c.transmit(a);
//
//			System.out.println(r);
//			if (r.getSW() != 0x9000)
//				throw new Exception("Exception on the card: " + r.getSW());
//
//			inc = r.getData();
//			System.out.println(new BigInteger(1, inc).toString(16));
//
//			if (simulator) {
//				System.out.println("Na filter.. \n" + new BigInteger(1, filterSimulator(inc, a)).toString(16));
//			}
//
//			/**
//			 * 8026000000044a616e20 die 80 26 000 000 komt van 0x80 (CLA), 0x26
//			 * (INS) en dan die 2x 000 door 0x00 (p1 en p2) wat volgt is dan die
//			 * ins_file uit IDcard.java
//			 */
//
//			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
//			byte[] bytes = new byte[20];
//			random.nextBytes(bytes);
//
//			// 5. sign iets instruction
//			a = new CommandAPDU(IDENTITY_CARD_CLA, SIGN_INS, 0x00, 0x00, bytes);
//			r = c.transmit(a);
//
//			System.out.println(r);
//			if (r.getSW() != 0x9000)
//				throw new Exception("Exception on the card: " + r.getSW());
//
//			byte[] signedChallenge = r.getData();
//
//			System.out.println(new BigInteger(1, signedChallenge).toString(16));
//
//			if (simulator) {
//				System.out.println(
//						"Na filter.. \n" + new BigInteger(1, filterSimulator(signedChallenge, a)).toString(16));
//			}
//
//			// 6. vraag lengte van certificate <-> hangt samen met 7.
//			a = new CommandAPDU(IDENTITY_CARD_CLA, ASK_LENGTH_INS, 0x00, 0x00, 0xff);
//			r = c.transmit(a);
//
//			System.out.println(r);
//			if (r.getSW() != 0x9000)
//				throw new Exception("Exception on the card: " + r.getSW());
//
//			byte[] kappa = r.getData();
//
//			if (simulator) {
//				System.out.println("Na filter.. ");
//				kappa = filterSimulator(kappa, a);
//			}
//
//			int size = 0;
//
//			size += unsignedKK(kappa[0]) * 100;
//			size += unsignedKK(kappa[1]);
//
//			System.out.println("Kappa size: " + size);
//
//			System.out.println("Echte size: " + certificate.length); // debug..
//
//			if (size == certificate.length)
//				System.out.println("Insert MIMIMI song pls");
//
//			int aantalCalls = (int) Math.ceil((double) size / 240);
//			System.out.println("Aantal calls: " + aantalCalls);
//
//			// 7. haal certificate op, op basis van aantalCalls
//			byte[] finalCertificate = new byte[size];
//
//			byte[] certificate = new byte[0];
//
//			for (int i = 0; i < aantalCalls; i++) {
//				// doe nu uw calls, pleb
//				a = new CommandAPDU(IDENTITY_CARD_CLA, GET_CERT_INS, (byte) i, 0x00, 0xff);
//				r = c.transmit(a);
//
//				System.out.println(r);
//				if (r.getSW() != 0x9000)
//					throw new Exception("Exception on the card: " + r.getSW());
//
//				// finalCertificate.append(r.getData()); --> lukt ni :(
//				// voorlopig 1 voor 1 uitschrijven
//
//				System.out.println(r.getData().toString());
//
//				inc = r.getData();
//				for (byte b : inc)
//					System.out.print(b);
//
//				byte[] certificateTEMP = new byte[certificate.length + inc.length];
//
//				System.arraycopy(certificate, 0, certificateTEMP, 0, certificate.length);
//				System.arraycopy(inc, 0, certificateTEMP, certificate.length, inc.length);
//
//				certificate = certificateTEMP;
//				System.out.println("");
//			}
//
//			for (int i = 0; i < size; i++) {
//				finalCertificate[i] = certificate[i];
//			}
//
//			System.out.println("Certificaat:");
//			for (byte b : finalCertificate) {
//				System.out.print(b + " ");
//			}
//			System.out.println("");
//
//			// 8. vorm certicate om
//			CertificateFactory certFac = CertificateFactory.getInstance("X.509");
//			InputStream is = new ByteArrayInputStream(finalCertificate);
//			X509Certificate cert = (X509Certificate) certFac.generateCertificate(is);
//
//			// gebruik van 5.
//			// --> challenge: var bytes
//			// --> sign response: var signedChallenge
//
//			Signature signature = Signature.getInstance("SHA1withRSA");
//			signature.initVerify(cert.getPublicKey());
//			signature.update(bytes);
//			boolean ok = signature.verify(signedChallenge);
//
//			System.out.println("Signature verification: " + ok);
//		} catch (Exception e) {
//			throw e;
//		} finally {
//			c.close(); // close the connection with the card
//		}
	}

	public static int unsignedKK(byte x) {
		return (int) (x & 0xFF);
	}

	public static byte[] filterSimulator(byte[] inc, CommandAPDU a) {
		System.out.println(inc.length);
		int abc = 5;

		//if a.. dan moet abc 6 worden. :/ /**TODO**/
		
		byte[] rreturn = new byte[inc.length - abc];
		for (int i = 0; i < inc.length; i++) {
			if (i < abc) {
				System.out.println("DUMPING... " + inc[i]);
			} else {
				if (i == abc)
					System.out.println("START... " + inc[i]);
				rreturn[i - abc] = inc[i];
			}
		}
		return rreturn;
	}
}
