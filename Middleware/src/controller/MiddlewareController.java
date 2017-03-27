package controller;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import be.msec.client.Keys;
import be.msec.client.connection.Connection;
import be.msec.client.connection.IConnection;
import be.msec.client.connection.SimulatedConnection;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.TextArea;
import ssl.SSLConnectionServiceProvider;
import ssl.SSLConnectionTimeServer;

public class MiddlewareController {

	private final static byte IDENTITY_CARD_CLA = (byte) 0x80;
	private static final byte VALIDATE_PIN_INS = 0x22;
	private static final byte GET_IDENTITY_INS = 0x26;
	private static final byte GET_NAME_INS = 0x24;
	private static final byte SIGN_INS = 0x28;
	private static final byte ASK_LENGTH_INS = 0x30;
	private static final byte GET_CERT_INS = 0x32;

	private static final byte SET_TEMPTIME_INS = 0x40;
	private static final byte VALIDATE_TIME_INS = 0x42;
	private static final byte UPDATE_TIME_INS = 0x44;

	private static final byte SEND_SIG_INS = 0x46;
	private static final byte SEND_SIG_TIME_INS = 0x48;

	private static final byte SEND_CERT_INS = 0x41;

	private final static short SW_VERIFICATION_FAILED = 0x6322;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6323;
	private final static short KAPPA = 0x6337;
	private final static short VERIFY_FAILED = 0x6338;
	private final static short VERIFY_EXCEPTION_THROWN = 0x6339;

	// getjoept.. moet nog aangepast worden aan eigen certificaten
	// gebruik momenteel overal dezelfde :')
	private byte[] dummyPrivExponent = new byte[] { (byte) 0x64, (byte) 0xc2, (byte) 0x8d, (byte) 0xcf, (byte) 0xa1, (byte) 0x1a, (byte) 0x7e, (byte) 0x6a, (byte) 0xc9, (byte) 0x42, (byte) 0xf7, (byte) 0xb6, (byte) 0xad, (byte) 0x86, (byte) 0xdb, (byte) 0xf5, (byte) 0x20, (byte) 0x7c, (byte) 0xcd, (byte) 0x4d, (byte) 0xe9, (byte) 0xfb, (byte) 0x2e, (byte) 0x2b, (byte) 0x99, (byte) 0xfa, (byte) 0x29, (byte) 0x1e, (byte) 0xd9, (byte) 0xbd, (byte) 0xf9, (byte) 0xb2, (byte) 0x77, (byte) 0x9e, (byte) 0x3e, (byte) 0x1a, (byte) 0x60, (byte) 0x67, (byte) 0x8e, (byte) 0xbd, (byte) 0xae, (byte) 0x36, (byte) 0x54, (byte) 0x4a, (byte) 0x11, (byte) 0xc2, (byte) 0x2e, (byte) 0x7c, (byte) 0x9e, (byte) 0xc3, (byte) 0xcb, (byte) 0xba, (byte) 0x65, (byte) 0x2b, (byte) 0xc5, (byte) 0x1b, (byte) 0x6f, (byte) 0x4f, (byte) 0x54, (byte) 0xe1, (byte) 0xff, (byte) 0xc3, (byte) 0x18, (byte) 0x81 };
	private byte[] dummyPrivModulus = new byte[] { (byte) 0x8d, (byte) 0x08, (byte) 0x00, (byte) 0x7e, (byte) 0x39, (byte) 0xb1, (byte) 0x52, (byte) 0x4e, (byte) 0xc8, (byte) 0x90, (byte) 0x90, (byte) 0x37, (byte) 0x93, (byte) 0xd1, (byte) 0xcc, (byte) 0x33, (byte) 0xa8, (byte) 0x8d, (byte) 0xd5, (byte) 0x88, (byte) 0x7d, (byte) 0x5c, (byte) 0xcc, (byte) 0x8a, (byte) 0x26, (byte) 0xaa, (byte) 0x05, (byte) 0x2d, (byte) 0x7c, (byte) 0xed, (byte) 0xd9, (byte) 0xc4, (byte) 0xec, (byte) 0x89, (byte) 0x4e, (byte) 0x27, (byte) 0x85, (byte) 0x9b, (byte) 0x33, (byte) 0x43, (byte) 0x72, (byte) 0xae, (byte) 0xe2, (byte) 0xc8, (byte) 0x4d, (byte) 0x7c, (byte) 0x04, (byte) 0x02, (byte) 0xcd, (byte) 0x46, (byte) 0xf0, (byte) 0x3b, (byte) 0xd8, (byte) 0xa0, (byte) 0xb9, (byte) 0xd1, (byte) 0x9d, (byte) 0x33, (byte) 0x44, (byte) 0xe1, (byte) 0xfa, (byte) 0x0d, (byte) 0xf6, (byte) 0x69 };
	private byte[] dummyPubExponent = new byte[] { (byte) 0x01, (byte) 0x00, (byte) 0x01 };
	private byte[] dummyPubModulus = new byte[] { (byte) 0x8d, (byte) 0x08, (byte) 0x00, (byte) 0x7e, (byte) 0x39, (byte) 0xb1, (byte) 0x52, (byte) 0x4e, (byte) 0xc8, (byte) 0x90, (byte) 0x90, (byte) 0x37, (byte) 0x93, (byte) 0xd1, (byte) 0xcc, (byte) 0x33, (byte) 0xa8, (byte) 0x8d, (byte) 0xd5, (byte) 0x88, (byte) 0x7d, (byte) 0x5c, (byte) 0xcc, (byte) 0x8a, (byte) 0x26, (byte) 0xaa, (byte) 0x05, (byte) 0x2d, (byte) 0x7c, (byte) 0xed, (byte) 0xd9, (byte) 0xc4, (byte) 0xec, (byte) 0x89, (byte) 0x4e, (byte) 0x27, (byte) 0x85, (byte) 0x9b, (byte) 0x33, (byte) 0x43, (byte) 0x72, (byte) 0xae, (byte) 0xe2, (byte) 0xc8, (byte) 0x4d, (byte) 0x7c, (byte) 0x04, (byte) 0x02, (byte) 0xcd, (byte) 0x46, (byte) 0xf0, (byte) 0x3b, (byte) 0xd8, (byte) 0xa0, (byte) 0xb9, (byte) 0xd1, (byte) 0x9d, (byte) 0x33, (byte) 0x44, (byte) 0xe1, (byte) 0xfa, (byte) 0x0d, (byte) 0xf6, (byte) 0x69 };

	@FXML
	private TextArea communicationArea;

	private static IConnection connection;

	@FXML
	void loginSimulator(ActionEvent event) {
		startSimulator();
		System.out.println("Sending Pin..");
		sendPin();
		System.out.println("Complete! \n");

		System.out.println("Sending Time..");
		boolean isValid = isValid();
		System.out.println("revalidation needed: " + !isValid);
		System.out.println("Complete! \n");

		if (!isValid) {
			System.out.println("Sending Revalidation..");
			sendNewTime(fetchNewTime());
			System.out.println("Complete! \n");
		}

		/*** STAP 2 ***/
		System.out.println("Fetching SP certificate and passing it to SC..");
		authenticateServiceProvider( /**
										 * steek hier nog waarde in voor wie
										 * willen we auth?
										 **/
		);

	}

	@FXML
	void login(ActionEvent event) {

		try {
			/* Real Card: */
			connection = new Connection();
			((Connection) connection).setTerminal(0);
			// depending on which cardreader you use
			connection.connect();
		} catch (Exception e) {
			e.printStackTrace();
		}

		System.out.println("Sending Pin..");
		sendPin();
		System.out.println("Complete! \n");

		// System.out.println("Getting Name..");
		// getName();
		// System.out.println("Complete! \n");
		//
		// System.out.println("Signing test..");
		// signTest();
		// System.out.println("Complete! \n");

		/*** STAP 1 ***/
		System.out.println("Sending Time..");
		boolean isValid = isValid();
		System.out.println("Revalidation needed: " + !isValid);
		System.out.println("Complete! \n");

		if (!isValid) {
			sendNewTime(fetchNewTime());
		}

		/*** STAP 2 ***/
		System.out.println("Fetching SP certificate and passing it to SC..");
		authenticateServiceProvider( /**
										 * steek hier nog waarde in voor wie
										 * willen we auth?
										 **/
		);
	}

	private void startSimulator() {
		/* Simulation: */
		this.connection = new SimulatedConnection();

		CommandAPDU a;
		ResponseAPDU r;

		try {

			this.connection.connect();

			// 0. create applet (only for simulator!!!)
			a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00, new byte[] { (byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08, 0x01 }, 0x7f);
			r = this.connection.transmit(a);
			System.out.println(r);
			if (r.getSW() != 0x9000)
				throw new Exception("select installer applet failed");

			a = new CommandAPDU(0x80, 0xB8, 0x00, 0x00, new byte[] { 0xb, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00 }, 0x7f);
			r = this.connection.transmit(a);
			System.out.println(r);
			if (r.getSW() != 0x9000)
				throw new Exception("Applet creation failed");

			// 1. Select applet (not required on a real card, applet is selected
			// by default)
			a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00, new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00 }, 0x7f);
			r = this.connection.transmit(a);
			System.out.println(r);
			if (r.getSW() != 0x9000)
				throw new Exception("Applet selection failed");

			// 2. Send PIN
			// a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00,
			// 0x00, new byte[] { 0x01, 0x02, 0x03, 0x04 });
			// r = this.connection.transmit(a);
			//
			// System.out.println(r);
			// if (r.getSW() == SW_VERIFICATION_FAILED)
			// throw new Exception("PIN INVALID");
			// else if (r.getSW() != 0x9000)
			// throw new Exception("Exception on the card: " +
			// Integer.toHexString(r.getSW()));
			// System.out.println("PIN Verified");
			sendPin();

		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private void sendPin() {
		try {
			// authenticate();
			// byte[] encryptedPin = encryptWithPublicKeySC(new byte[] { 0x01,
			// 0x02, 0x03, 0x04 });

			CommandAPDU a;
			ResponseAPDU r;
			// 2. Send PIN
			// a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00,
			// 0x00, encryptedPin);
			a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00, new byte[] { 0x01, 0x02, 0x03, 0x04 });

			addText("Sending PIN to card");
			r = connection.transmit(a);
			addText("Received response on PIN instruction");

			System.out.println("\t Response: " + r);
			System.out.println("\t Response: " + Arrays.toString(r.getData()));
			if (r.getSW() == SW_VERIFICATION_FAILED) {
				addText("PIN INVALID");
				throw new Exception("PIN INVALID");
			} else if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + Integer.toHexString(r.getSW()));
			System.out.println("PIN Verified");
			addText("PIN Verified");
		} catch (Exception e) {
			System.out.println("You fucked up the pin");
			e.printStackTrace();
			System.exit(-1);
		}
	}

	private boolean isValid() {
		try {
			CommandAPDU a;
			ResponseAPDU r;
			// 2. Send Time

			// Seconden sinds epoch
			int unixTime = (int) (System.currentTimeMillis() / 1000);
			byte[] bytes = intToByteArray(unixTime);

			// System.out.println("\t \t DEBUG - current epoch " +
			// Arrays.toString(bytes) + " (" + unixTime + ")");

			// byte[] bytes1 = intToByteArray((int) (1483228800));
			// System.out.println("\t \t DEBUG - 1 jan 2017 " +
			// Arrays.toString(bytes1) + " (" + 1483228800 + ")");

			// byte[] bytes2 = intToByteArray((int) (1512086400));
			// System.out.println("\t \t DEBUG - 1 dec 2017 " +
			// Arrays.toString(bytes2) + " (" + 1512086400 + ")");

			intToByteArray(unixTime + 200000);
			intToByteArray(unixTime - 90000);

			for (int i = 0; i < 3; i += 2) {
				a = new CommandAPDU(IDENTITY_CARD_CLA, SET_TEMPTIME_INS, bytes[i], bytes[i + 1], 0xff);
				r = connection.transmit(a);

				if (r.getSW() == SW_VERIFICATION_FAILED) {
					addText("PIN INVALID");
					throw new Exception("PIN INVALID");
				} else if (r.getSW() != 0x9000)
					throw new Exception("Exception on the card: " + Integer.toHexString(r.getSW()));

				addText("Receive an answer regarding time (" + i + ")");
				System.out.println("\t Response: " + r);
			}

			a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_TIME_INS, 0x00, 0x00, 0xff);
			r = connection.transmit(a);

			addText("Received final answer regarding time");

			System.out.println("\t Response: " + r);
			addText(Arrays.toString(r.getData()));
			if (r.getSW() == SW_VERIFICATION_FAILED) {
				addText("PIN INVALID");
				throw new Exception("PIN INVALID");
			} else if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + Integer.toHexString(r.getSW()));

			byte[] inc = r.getData();

			System.out.println("\t Payload: " + Arrays.toString(inc));
			System.out.println("\t Payload: " + new BigInteger(1, inc).toString(16));

			addText("Action performed correctly");

			if (inc[0] == (byte) 1)
				return true;
		} catch (Exception e) {
			System.out.println("You fucked up");
			e.printStackTrace();
			System.exit(-1);
		}

		return false;
	}

	private String[] fetchNewTime() {
		SSLConnectionTimeServer c = new SSLConnectionTimeServer();
		return c.fetchTime();
	}

	private void sendNewTime(String[] time) {
		try {
			CommandAPDU a;
			ResponseAPDU r;

			// time[0] = sig;
			// time[1] = time;

			/** send signature to JC **/
			byte[] bytes = intToByteArray(Integer.parseInt(time[1]));

			a = new CommandAPDU(IDENTITY_CARD_CLA, SEND_SIG_TIME_INS, 0x00, 0x00, bytes);
			r = connection.transmit(a);

			if (r.getSW() == SW_VERIFICATION_FAILED) {
				addText("PIN INVALID");
				throw new Exception("PIN INVALID");
			} else if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + Integer.toHexString(r.getSW()));

			System.out.println("\tTime was sent to card, no exceptions met");

			/** send signature to JC **/
			bytes = SSLConnectionTimeServer.hexStringToByteArray(time[0]);

			a = new CommandAPDU(IDENTITY_CARD_CLA, SEND_SIG_INS, 0x00, 0x00, bytes);
			r = connection.transmit(a);

			if (r.getSW() == SW_VERIFICATION_FAILED) {
				addText("PIN INVALID");
				throw new Exception("PIN INVALID");
			} else if (r.getSW() == VERIFY_EXCEPTION_THROWN) {
				addText("VERIFY EXCEPTION WAS THROWN, RIP ALGORITHM?");
				throw new Exception("VERIFY EXCEPTION WAS THROWN, RIP ALGORITHM?");
			} else if (r.getSW() == VERIFY_FAILED) {
				addText("SIGNATURE INVALID");
				throw new Exception("SIGNATURE INVALID");
			} else if (r.getSW() != 0x9000)
				throw new Exception("\tException on the card: " + Integer.toHexString(r.getSW()));

			addText("sendNewTime performed correctly");
		} catch (Exception e) {
			// do nothing... TODO fix deze shit
			System.out.println("\t" + e.getMessage());
		}
	}

	private void signTest() {
		/**
		 * 8026000000044a616e20 die 80 26 000 000 komt van 0x80 (CLA), 0x26
		 * (INS) en dan die 2x 000 door 0x00 (p1 en p2) wat volgt is dan die
		 * ins_file uit IDcard.java
		 */
		try {
			CommandAPDU a;
			ResponseAPDU r;

			SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
			byte[] bytes = new byte[20];
			random.nextBytes(bytes);

			// 5. sign iets instruction
			System.out.println("Original data: " + Arrays.toString(bytes));
			a = new CommandAPDU(IDENTITY_CARD_CLA, SIGN_INS, 0x00, 0x00, bytes);
			r = connection.transmit(a);

			System.out.println(r);
			if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + Integer.toHexString(r.getSW()));

			byte[] signedChallenge = r.getData();

			System.out.println("\t Payload: " + Arrays.toString(signedChallenge));
			System.out.println("\t Payload: " + new BigInteger(1, signedChallenge).toString(16));
		} catch (Exception e) {
			System.out.println("You fucked up");
			e.printStackTrace();
		}
	}

	private void getName() {
		try {
			CommandAPDU a;
			ResponseAPDU r;
			a = new CommandAPDU(IDENTITY_CARD_CLA, GET_NAME_INS, 0x00, 0x00, 0xff);
			r = connection.transmit(a);

			System.out.println(r);
			if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + Integer.toHexString(r.getSW()));

			byte[] inc = r.getData();
			System.out.println("\t Payload: " + Arrays.toString(inc));
			System.out.println("\t Payload: " + new BigInteger(1, inc).toString(16));

			/**
			 * 8026000000044a616e20 die 80 26 000 000 komt van 0x80 (CLA), 0x26
			 * (INS) en dan die 2x 000 door 0x00 (p1 en p2) wat volgt is dan die
			 * ins_file uit IDcard.java
			 */
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void authenticateServiceProvider() {
		byte[] cert = fetchCert();

		CommandAPDU a;
		ResponseAPDU r;

		/** send cert part 1 to JC **/
		try {
			byte[] send = new byte[250];
			for (int i = 0; i < 250; i++) {
				send[i] = cert[i];
			}

			System.out.println("\tSending (" + send.length + "): " + Arrays.toString(send));
			a = new CommandAPDU(IDENTITY_CARD_CLA, SEND_CERT_INS, (byte) 1, 0x00, send);
			r = connection.transmit(a);

			if (r.getSW() == SW_VERIFICATION_FAILED) {
				addText("PIN INVALID");
				throw new Exception("PIN INVALID");
			} else if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + Integer.toHexString(r.getSW()));

			send = new byte[cert.length - 250];
			for (int i = 0; i < cert.length - 250; i++) {
				send[i] = cert[i + 250];
			}

			System.out.println("\tSending (" + send.length + "): " + Arrays.toString(send));
			a = new CommandAPDU(IDENTITY_CARD_CLA, SEND_CERT_INS, (byte) 2, 0x00, send);
			r = connection.transmit(a);

			if (r.getSW() == SW_VERIFICATION_FAILED) {
				addText("PIN INVALID");
				throw new Exception("PIN INVALID");
			} else if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + Integer.toHexString(r.getSW()));

			System.out.println("\tCert was sent to card, no exceptions met");

			/** DEBUG GET CERT IN ORDER TO VERIFY **/
			// // 6. vraag lengte van certificate <-> hangt samen met 7.
			// a = new CommandAPDU(IDENTITY_CARD_CLA, ASK_LENGTH_INS, 0x00,
			// 0x00, 0xff);
			// r = connection.transmit(a);
			//
			// if (r.getSW() != 0x9000)
			// throw new Exception("Exception on the card: " +
			// Integer.toHexString(r.getSW()));
			//
			// byte[] kappa = r.getData();
			//
			// int size = 0;
			//
			// size += unsigned(kappa[0]) * 100;
			// size += unsigned(kappa[1]);
			//
			// System.out.println("Kappa size: " + size);
			//
			// int aantalCalls = (int) Math.ceil((double) size / 240);
			// System.out.println("Aantal calls: " + aantalCalls);
			//
			// // 7. haal certificate op, op basis van aantalCalls
			// byte[] finalCertificate = new byte[size];
			//
			// byte[] certificate = new byte[0];
			//
			// for (int i = 0; i < aantalCalls; i++) {
			// // doe nu uw calls, pleb
			// a = new CommandAPDU(IDENTITY_CARD_CLA, GET_CERT_INS, (byte) i,
			// 0x00, 0xff);
			// r = connection.transmit(a);
			//
			// System.out.println(r);
			// if (r.getSW() != 0x9000)
			// throw new Exception("Exception on the card: " +
			// Integer.toHexString(r.getSW()));
			//
			// byte[] inc = r.getData();
			// byte[] certificateTEMP = new byte[certificate.length +
			// inc.length];
			//
			// System.arraycopy(certificate, 0, certificateTEMP, 0,
			// certificate.length);
			// System.arraycopy(inc, 0, certificateTEMP, certificate.length,
			// inc.length);
			//
			// certificate = certificateTEMP;
			// System.out.println("");
			// }
			//
			// for (int i = 0; i < size; i++) {
			// finalCertificate[i] = certificate[i];
			// }
			//
			// System.out.println("Certificaat: " +
			// Arrays.toString(finalCertificate));

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private byte[] fetchCert() {
		SSLConnectionServiceProvider c = new SSLConnectionServiceProvider();
		return c.fetchCert(/** hier waarde in meegeven? **/
		);
	}

	public static void sendData(byte command, byte p1, byte p2, byte[] data) throws Exception {
		System.out.println("Send data (length " + data.length + "): ");

		CommandAPDU a;
		ResponseAPDU r;

		a = new CommandAPDU(IDENTITY_CARD_CLA, command, p1, p2, data, 0xff);
		r = connection.transmit(a);
		if (r.getSW() != 0x9000)
			throw new Exception(command + " failed " + r);
	}

	@FXML
	void logout(ActionEvent event) {
		try {
			connection.close();
			addText("Connection closed");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public void addText(String text) {
		communicationArea.appendText(text + "\n");
	}

	public IConnection getConnection() {
		return connection;
	}

	public void setConnection(IConnection c) {
		this.connection = (Connection) c;
	}

	private byte[] intToByteArray(final int i) {
		BigInteger bigInt = BigInteger.valueOf(i);
		System.out.print("\tConverting " + i + " ...");
		System.out.println(" converted to " + Arrays.toString(bigInt.toByteArray()));
		return bigInt.toByteArray();
	}

	private BigInteger byteArrayToInt(final byte[] b) {
		return new BigInteger(b);
	}

	private static byte[] sendInsAndReceive(byte command, boolean encryptedMW) throws Exception {
		return sendInsAndReceive(command, (byte) 0x00, (byte) 0x00, encryptedMW);
	}

	private static byte[] sendInsAndReceive(byte command, byte p1, byte p2, boolean encryptedMW) throws Exception {
		CommandAPDU a;
		ResponseAPDU r;

		// System.out.println("Send instruction: [command "+command+" p1 "+p1+"
		// p2
		// "+p2+"]");
		a = new CommandAPDU(IDENTITY_CARD_CLA, command, p1, p2, 0xff);
		r = connection.transmit(a);
		if (r.getSW() != 0x9000)
			throw new Exception(command + " failed " + r + " SW: " + Integer.toHexString(r.getSW()));

		// System.out.println("Received encrypted data (length
		// "+r.getData().length+"): "); Util.printBytes(r.getData());
		if (encryptedMW)
			return decryptWithPrivateKey(r.getData());
		else
			return r.getData();
	}

	public static byte[] decryptWithPrivateKey(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Cipher asymCipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");

		asymCipher.init(Cipher.DECRYPT_MODE, Keys.getMyPrivateRSAKey());
		return asymCipher.doFinal(data);
	}

	public static byte[] encryptWithPublicKeySC(byte[] data) throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		System.out.println("\n \t Data to encrypt: " + Arrays.toString(data));

		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Cipher asymCipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");

		asymCipher.init(Cipher.ENCRYPT_MODE, Keys.getPublicSCKey());

		byte[] encryptedData = asymCipher.doFinal(data);

		System.out.println("\t Data encrypted (length " + encryptedData.length + "): ");
		System.out.println("\t " + Arrays.toString(encryptedData));

		return encryptedData;
	}

	public int unsigned(byte x) {
		return (x & 0xFF);
	}
	// try {
	//
	// /*
	// * For more info on the use of CommandAPDU and ResponseAPDU: See
	// * http://java.sun.com/javase/6/docs/jre/api/security/smartcardio/
	// * spec/index.html
	// */
	//
	// CommandAPDU a;
	// ResponseAPDU r;
	//
	// boolean simulator = false;
	////
	//// // 0. create applet (only for simulator!!!)
	//// a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,
	//// new byte[] { (byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08,
	// 0x01 }, 0x7f);
	//// r = c.transmit(a);
	//// System.out.println(r);
	//// if (r.getSW() != 0x9000)
	//// throw new Exception("select installer applet failed");
	////
	//// a = new CommandAPDU(0x80, 0xB8, 0x00, 0x00,
	//// new byte[] { 0xb, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	// 0x00, 0x00, 0x00 }, 0x7f);
	//// r = c.transmit(a);
	//// System.out.println(r);
	//// if (r.getSW() != 0x9000)
	//// throw new Exception("Applet creation failed");
	////
	//// // 1. Select applet (not required on a real card, applet is selected
	//// // by default)
	//// a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,
	//// new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
	// 0x00, 0x00 }, 0x7f);
	//// r = c.transmit(a);
	//// System.out.println(r);
	//// if (r.getSW() != 0x9000)
	//// throw new Exception("Applet selection failed");
	//
	// // 2. Send PIN
	// a = new CommandAPDU(IDENTITY_CARD_CLA, VALIDATE_PIN_INS, 0x00, 0x00, new
	// byte[] { 0x01, 0x02, 0x03, 0x04 });
	// r = c.transmit(a);
	//
	// System.out.println(r);
	// if (r.getSW() == SW_VERIFICATION_FAILED)
	// throw new Exception("PIN INVALID");
	// else if (r.getSW() != 0x9000)
	// throw new Exception("Exception on the card: " +
	// Integer.toHexString(r.getSW()));
	// System.out.println("PIN Verified");
	//
	// // 3. Get identity instruction
	// a = new CommandAPDU(IDENTITY_CARD_CLA, GET_IDENTITY_INS, 0x00, 0x00,
	// 0xff);
	// r = c.transmit(a);
	//
	// System.out.println(r);
	// if (r.getSW() != 0x9000)
	// throw new Exception("Exception on the card: " +
	// Integer.toHexString(r.getSW()));
	//
	// byte[] inc = r.getData();
	//
	// System.out.println(new BigInteger(1, inc).toString(16));
	//
	// if (simulator) {
	// System.out.println("Na filter.. \n" + new BigInteger(1,
	// filterSimulator(inc, a)).toString(16));
	// }
	//
	// /**
	// *
	// 8024000000374a616e20566f737361657274200a416674616e736520737465656e7765672033200a39303030200a47656e74200a6d616e200a31393837)
	// * die 80 24 000 000 komt van 0x80 (CLA), 0x24 (INS) en dan die 2x
	// * 000 door 0x00 (p1 en p2) wat volgt is dan die ins_file uit
	// * IDcard.java
	// *
	// * ^enkel op simulator ;-;
	// */
	//
	// // 4. get name instruction
	// a = new CommandAPDU(IDENTITY_CARD_CLA, GET_NAME_INS, 0x00, 0x00, 0xff);
	// r = c.transmit(a);
	//
	// System.out.println(r);
	// if (r.getSW() != 0x9000)
	// throw new Exception("Exception on the card: " +
	// Integer.toHexString(r.getSW()));
	//
	// inc = r.getData();
	// System.out.println(new BigInteger(1, inc).toString(16));
	//
	// if (simulator) {
	// System.out.println("Na filter.. \n" + new BigInteger(1,
	// filterSimulator(inc, a)).toString(16));
	// }
	//
	// /**
	// * 8026000000044a616e20 die 80 26 000 000 komt van 0x80 (CLA), 0x26
	// * (INS) en dan die 2x 000 door 0x00 (p1 en p2) wat volgt is dan die
	// * ins_file uit IDcard.java
	// */
	//
	// SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
	// byte[] bytes = new byte[20];
	// random.nextBytes(bytes);
	//
	// // 5. sign iets instruction
	// a = new CommandAPDU(IDENTITY_CARD_CLA, SIGN_INS, 0x00, 0x00, bytes);
	// r = c.transmit(a);
	//
	// System.out.println(r);
	// if (r.getSW() != 0x9000)
	// throw new Exception("Exception on the card: " +
	// Integer.toHexString(r.getSW()));
	//
	// byte[] signedChallenge = r.getData();
	//
	// System.out.println(new BigInteger(1, signedChallenge).toString(16));
	//
	// if (simulator) {
	// System.out.println(
	// "Na filter.. \n" + new BigInteger(1, filterSimulator(signedChallenge,
	// a)).toString(16));
	// }
	//
	// // 6. vraag lengte van certificate <-> hangt samen met 7.
	// a = new CommandAPDU(IDENTITY_CARD_CLA, ASK_LENGTH_INS, 0x00, 0x00, 0xff);
	// r = c.transmit(a);
	//
	// System.out.println(r);
	// if (r.getSW() != 0x9000)
	// throw new Exception("Exception on the card: " +
	// Integer.toHexString(r.getSW()));
	//
	// byte[] kappa = r.getData();
	//
	// if (simulator) {
	// System.out.println("Na filter.. ");
	// kappa = filterSimulator(kappa, a);
	// }
	//
	// int size = 0;
	//
	// size += unsignedKK(kappa[0]) * 100;
	// size += unsignedKK(kappa[1]);
	//
	// System.out.println("Kappa size: " + size);
	//
	// System.out.println("Echte size: " + certificate.length); // debug..
	//
	// if (size == certificate.length)
	// System.out.println("Insert MIMIMI song pls");
	//
	// int aantalCalls = (int) Math.ceil((double) size / 240);
	// System.out.println("Aantal calls: " + aantalCalls);
	//
	// // 7. haal certificate op, op basis van aantalCalls
	// byte[] finalCertificate = new byte[size];
	//
	// byte[] certificate = new byte[0];
	//
	// for (int i = 0; i < aantalCalls; i++) {
	// // doe nu uw calls, pleb
	// a = new CommandAPDU(IDENTITY_CARD_CLA, GET_CERT_INS, (byte) i, 0x00,
	// 0xff);
	// r = c.transmit(a);
	//
	// System.out.println(r);
	// if (r.getSW() != 0x9000)
	// throw new Exception("Exception on the card: " +
	// Integer.toHexString(r.getSW()));
	//
	// // finalCertificate.append(r.getData()); --> lukt ni :(
	// // voorlopig 1 voor 1 uitschrijven
	//
	// System.out.println(r.getData().toString());
	//
	// inc = r.getData();
	// for (byte b : inc)
	// System.out.print(b);
	//
	// byte[] certificateTEMP = new byte[certificate.length + inc.length];
	//
	// System.arraycopy(certificate, 0, certificateTEMP, 0, certificate.length);
	// System.arraycopy(inc, 0, certificateTEMP, certificate.length,
	// inc.length);
	//
	// certificate = certificateTEMP;
	// System.out.println("");
	// }
	//
	// for (int i = 0; i < size; i++) {
	// finalCertificate[i] = certificate[i];
	// }
	//
	// System.out.println("Certificaat:");
	// for (byte b : finalCertificate) {
	// System.out.print(b + " ");
	// }
	// System.out.println("");
	//
	// // 8. vorm certicate om
	// CertificateFactory certFac = CertificateFactory.getInstance("X.509");
	// InputStream is = new ByteArrayInputStream(finalCertificate);
	// X509Certificate cert = (X509Certificate) certFac.generateCertificate(is);
	//
	// // gebruik van 5.
	// // --> challenge: var bytes
	// // --> sign response: var signedChallenge
	//
	// Signature signature = Signature.getInstance("SHA1withRSA");
	// signature.initVerify(cert.getPublicKey());
	// signature.update(bytes);
	// boolean ok = signature.verify(signedChallenge);
	//
	// System.out.println("Signature verification: " + ok);
	// } catch (Exception e) {
	// throw e;
	// } finally {
	// c.close(); // close the connection with the card
	// }

}
