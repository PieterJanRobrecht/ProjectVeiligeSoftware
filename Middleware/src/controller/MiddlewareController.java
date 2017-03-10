package controller;

import java.math.BigInteger;
import java.util.Arrays;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import be.msec.client.connection.Connection;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.TextArea;

public class MiddlewareController {

	private final static byte IDENTITY_CARD_CLA = (byte) 0x80;
	private static final byte VALIDATE_PIN_INS = 0x22;
	private static final byte GET_IDENTITY_INS = 0x26;
	private static final byte GET_NAME_INS = 0x24;
	private static final byte SIGN_INS = 0x28;
	private static final byte ASK_LENGTH_INS = 0x30;
	private static final byte GET_CERT_INS = 0x32;
	private static final byte VALIDATE_TIME_INS = 0x34;
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

	@FXML
	private TextArea communicationArea;

	private Connection connection;

	@FXML
	void login(ActionEvent event) {
		System.out.print("Sending Pin..");
		sendPin();
		System.out.println(" Complete!");
		System.out.print("Sending Time..");
		sendTime();
		System.out.println(" Complete!");
	}

	private void sendTime() {
		try {
			CommandAPDU a;
			ResponseAPDU r;
			// 2. Send Time

			// Seconden sinds epoch
			int unixTime = (int) (System.currentTimeMillis() / 1000);
			
			byte[] bytes = intToByteArray(unixTime);
			
			/*
			a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_TIME_INS, 0x00, 0x00, bytes, 0xff);
			addText("Sending time " + Arrays.toString(intToByteArray(unixTime)) + " to card");

			r = connection.transmit(a);
			addText("Received an answer");

			System.out.println(r);
			if (r.getSW() == SW_VERIFICATION_FAILED) {
				addText("PIN INVALID");
				throw new Exception("PIN INVALID");
			} else if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + r.getSW());

			byte[] inc = r.getData();

			System.out.println(new BigInteger(1, inc).toString(16));
			*/
			
			//a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_TIME_INS, unixTime, 0x00, 0xff);	
			a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_TIME_INS, 0x00, 0x00, bytes);
			r = connection.transmit(a);

			addText("Received an answer");
			
			System.out.println(r);
			if (r.getSW() == SW_VERIFICATION_FAILED) {
				addText("PIN INVALID");
				throw new Exception("PIN INVALID");
			} else if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + r.getSW());

			byte[] inc = r.getData();

			System.out.println(new BigInteger(1, inc).toString(16));
			
			
			addText("Action performed correctly");
		} catch (Exception e) {
			System.out.println("You fucked up");
			e.printStackTrace();
		}

	}

	private void sendPin() {
		try {
			IConnection c;

			/* Simulation: */
			// c = new SimulatedConnection();

			/* Real Card: */
			connection = new Connection();
			((Connection) connection).setTerminal(0);
			// depending on which cardreader you use
			connection.connect();

			CommandAPDU a;
			ResponseAPDU r;
			// 2. Send PIN
			a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00, new byte[] { 0x01, 0x02, 0x03, 0x04 });
			addText("Sending PIN to card");

			r = connection.transmit(a);
			addText("Received response on PIN instruction");

			System.out.println(r);
			if (r.getSW() == SW_VERIFICATION_FAILED) {
				addText("PIN INVALID");
				throw new Exception("PIN INVALID");
			} else if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + r.getSW());
			System.out.println("PIN Verified");
			addText("PIN Verified");
		} catch (Exception e) {
			System.out.println("You fucked up the pin");
			e.printStackTrace();
		}
	}

	@FXML
	void logout(ActionEvent event) {
		try {
			connection.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void addText(String text) {
		communicationArea.appendText(text + "\n");
	}

	public Connection getConnection() {
		return connection;
	}

	public void setConnection(IConnection c) {
		this.connection = (Connection) c;
	}

	private byte[] intToByteArray(final int i) {
		BigInteger bigInt = BigInteger.valueOf(i);
		return bigInt.toByteArray();
	}
	
//	try {
//
//		/*
//		 * For more info on the use of CommandAPDU and ResponseAPDU: See
//		 * http://java.sun.com/javase/6/docs/jre/api/security/smartcardio/
//		 * spec/index.html
//		 */
//
//		CommandAPDU a;
//		ResponseAPDU r;
//
//		boolean simulator = false;
////
////		// 0. create applet (only for simulator!!!)
////		a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,
////				new byte[] { (byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08, 0x01 }, 0x7f);
////		r = c.transmit(a);
////		System.out.println(r);
////		if (r.getSW() != 0x9000)
////			throw new Exception("select installer applet failed");
////
////		a = new CommandAPDU(0x80, 0xB8, 0x00, 0x00,
////				new byte[] { 0xb, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00 }, 0x7f);
////		r = c.transmit(a);
////		System.out.println(r);
////		if (r.getSW() != 0x9000)
////			throw new Exception("Applet creation failed");
////
////		// 1. Select applet (not required on a real card, applet is selected
////		// by default)
////		a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,
////				new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00 }, 0x7f);
////		r = c.transmit(a);
////		System.out.println(r);
////		if (r.getSW() != 0x9000)
////			throw new Exception("Applet selection failed");
//
//		// 2. Send PIN
//		a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00, new byte[] { 0x01, 0x02, 0x03, 0x04 });
//		r = c.transmit(a);
//
//		System.out.println(r);
//		if (r.getSW() == SW_VERIFICATION_FAILED)
//			throw new Exception("PIN INVALID");
//		else if (r.getSW() != 0x9000)
//			throw new Exception("Exception on the card: " + r.getSW());
//		System.out.println("PIN Verified");
//
//		// 3. Get identity instruction
//		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_IDENTITY_INS, 0x00, 0x00, 0xff);
//		r = c.transmit(a);
//
//		System.out.println(r);
//		if (r.getSW() != 0x9000)
//			throw new Exception("Exception on the card: " + r.getSW());
//
//		byte[] inc = r.getData();
//
//		System.out.println(new BigInteger(1, inc).toString(16));
//
//		if (simulator) {
//			System.out.println("Na filter.. \n" + new BigInteger(1, filterSimulator(inc, a)).toString(16));
//		}
//
//		/**
//		 * 8024000000374a616e20566f737361657274200a416674616e736520737465656e7765672033200a39303030200a47656e74200a6d616e200a31393837)
//		 * die 80 24 000 000 komt van 0x80 (CLA), 0x24 (INS) en dan die 2x
//		 * 000 door 0x00 (p1 en p2) wat volgt is dan die ins_file uit
//		 * IDcard.java
//		 * 
//		 * ^enkel op simulator ;-;
//		 */
//
//		// 4. get name instruction
//		a = new CommandAPDU(IDENTITY_CARD_CLA, GET_NAME_INS, 0x00, 0x00, 0xff);
//		r = c.transmit(a);
//
//		System.out.println(r);
//		if (r.getSW() != 0x9000)
//			throw new Exception("Exception on the card: " + r.getSW());
//
//		inc = r.getData();
//		System.out.println(new BigInteger(1, inc).toString(16));
//
//		if (simulator) {
//			System.out.println("Na filter.. \n" + new BigInteger(1, filterSimulator(inc, a)).toString(16));
//		}
//
//		/**
//		 * 8026000000044a616e20 die 80 26 000 000 komt van 0x80 (CLA), 0x26
//		 * (INS) en dan die 2x 000 door 0x00 (p1 en p2) wat volgt is dan die
//		 * ins_file uit IDcard.java
//		 */
//
//		SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
//		byte[] bytes = new byte[20];
//		random.nextBytes(bytes);
//
//		// 5. sign iets instruction
//		a = new CommandAPDU(IDENTITY_CARD_CLA, SIGN_INS, 0x00, 0x00, bytes);
//		r = c.transmit(a);
//
//		System.out.println(r);
//		if (r.getSW() != 0x9000)
//			throw new Exception("Exception on the card: " + r.getSW());
//
//		byte[] signedChallenge = r.getData();
//
//		System.out.println(new BigInteger(1, signedChallenge).toString(16));
//
//		if (simulator) {
//			System.out.println(
//					"Na filter.. \n" + new BigInteger(1, filterSimulator(signedChallenge, a)).toString(16));
//		}
//
//		// 6. vraag lengte van certificate <-> hangt samen met 7.
//		a = new CommandAPDU(IDENTITY_CARD_CLA, ASK_LENGTH_INS, 0x00, 0x00, 0xff);
//		r = c.transmit(a);
//
//		System.out.println(r);
//		if (r.getSW() != 0x9000)
//			throw new Exception("Exception on the card: " + r.getSW());
//
//		byte[] kappa = r.getData();
//
//		if (simulator) {
//			System.out.println("Na filter.. ");
//			kappa = filterSimulator(kappa, a);
//		}
//
//		int size = 0;
//
//		size += unsignedKK(kappa[0]) * 100;
//		size += unsignedKK(kappa[1]);
//
//		System.out.println("Kappa size: " + size);
//
//		System.out.println("Echte size: " + certificate.length); // debug..
//
//		if (size == certificate.length)
//			System.out.println("Insert MIMIMI song pls");
//
//		int aantalCalls = (int) Math.ceil((double) size / 240);
//		System.out.println("Aantal calls: " + aantalCalls);
//
//		// 7. haal certificate op, op basis van aantalCalls
//		byte[] finalCertificate = new byte[size];
//
//		byte[] certificate = new byte[0];
//
//		for (int i = 0; i < aantalCalls; i++) {
//			// doe nu uw calls, pleb
//			a = new CommandAPDU(IDENTITY_CARD_CLA, GET_CERT_INS, (byte) i, 0x00, 0xff);
//			r = c.transmit(a);
//
//			System.out.println(r);
//			if (r.getSW() != 0x9000)
//				throw new Exception("Exception on the card: " + r.getSW());
//
//			// finalCertificate.append(r.getData()); --> lukt ni :(
//			// voorlopig 1 voor 1 uitschrijven
//
//			System.out.println(r.getData().toString());
//
//			inc = r.getData();
//			for (byte b : inc)
//				System.out.print(b);
//
//			byte[] certificateTEMP = new byte[certificate.length + inc.length];
//
//			System.arraycopy(certificate, 0, certificateTEMP, 0, certificate.length);
//			System.arraycopy(inc, 0, certificateTEMP, certificate.length, inc.length);
//
//			certificate = certificateTEMP;
//			System.out.println("");
//		}
//
//		for (int i = 0; i < size; i++) {
//			finalCertificate[i] = certificate[i];
//		}
//
//		System.out.println("Certificaat:");
//		for (byte b : finalCertificate) {
//			System.out.print(b + " ");
//		}
//		System.out.println("");
//
//		// 8. vorm certicate om
//		CertificateFactory certFac = CertificateFactory.getInstance("X.509");
//		InputStream is = new ByteArrayInputStream(finalCertificate);
//		X509Certificate cert = (X509Certificate) certFac.generateCertificate(is);
//
//		// gebruik van 5.
//		// --> challenge: var bytes
//		// --> sign response: var signedChallenge
//
//		Signature signature = Signature.getInstance("SHA1withRSA");
//		signature.initVerify(cert.getPublicKey());
//		signature.update(bytes);
//		boolean ok = signature.verify(signedChallenge);
//
//		System.out.println("Signature verification: " + ok);
//	} catch (Exception e) {
//		throw e;
//	} finally {
//		c.close(); // close the connection with the card
//	}

}
