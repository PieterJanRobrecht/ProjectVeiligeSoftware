package controller;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.SSLServerSocketFactory;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Observable;
import java.util.Observer;

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
import ssl.MiddlewareServer;
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

	private static final byte SEND_CERT_INS = 0x50;
	private static final byte GET_KEY_INS = 0x52;
	private static final byte GET_MSG_INS = 0x54;

	private final static short SW_VERIFICATION_FAILED = 0x6322;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6323;
	private final static short KAPPA = 0x6337;
	private final static short VERIFY_FAILED = 0x6338;
	private final static short VERIFY_EXCEPTION_THROWN = 0x6339;
	private final static short ALG_FAILED = 0x6340;
	private final static short SEQUENTIAL_FAILURE = 0x6341;

	// getjoept.. moet nog aangepast worden aan eigen certificaten
	// gebruik momenteel overal dezelfde :')
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

	// Gemaakt aan de hand van goede certificaten?
	private byte[] certCA = new byte[] { (byte) 48, (byte) -126, (byte) 1, (byte) -39, (byte) 48, (byte) -126, (byte) 1,
			(byte) -125, (byte) -96, (byte) 3, (byte) 2, (byte) 1, (byte) 2, (byte) 2, (byte) 9, (byte) 0, (byte) -93,
			(byte) 38, (byte) 118, (byte) 61, (byte) 72, (byte) -98, (byte) 45, (byte) 71, (byte) 48, (byte) 13,
			(byte) 6, (byte) 9, (byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1,
			(byte) 1, (byte) 11, (byte) 5, (byte) 0, (byte) 48, (byte) 72, (byte) 49, (byte) 11, (byte) 48, (byte) 9,
			(byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 6, (byte) 19, (byte) 2, (byte) 66, (byte) 69, (byte) 49,
			(byte) 19, (byte) 48, (byte) 17, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 8, (byte) 12, (byte) 10,
			(byte) 83, (byte) 111, (byte) 109, (byte) 101, (byte) 45, (byte) 83, (byte) 116, (byte) 97, (byte) 116,
			(byte) 101, (byte) 49, (byte) 17, (byte) 48, (byte) 15, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 10,
			(byte) 12, (byte) 8, (byte) 67, (byte) 101, (byte) 114, (byte) 116, (byte) 65, (byte) 117, (byte) 116,
			(byte) 104, (byte) 49, (byte) 17, (byte) 48, (byte) 15, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 3,
			(byte) 12, (byte) 8, (byte) 67, (byte) 101, (byte) 114, (byte) 116, (byte) 65, (byte) 117, (byte) 116,
			(byte) 104, (byte) 48, (byte) 30, (byte) 23, (byte) 13, (byte) 49, (byte) 55, (byte) 48, (byte) 51,
			(byte) 50, (byte) 55, (byte) 49, (byte) 49, (byte) 52, (byte) 52, (byte) 53, (byte) 53, (byte) 90,
			(byte) 23, (byte) 13, (byte) 50, (byte) 50, (byte) 48, (byte) 51, (byte) 50, (byte) 55, (byte) 49,
			(byte) 49, (byte) 52, (byte) 52, (byte) 53, (byte) 53, (byte) 90, (byte) 48, (byte) 72, (byte) 49,
			(byte) 11, (byte) 48, (byte) 9, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 6, (byte) 19, (byte) 2,
			(byte) 66, (byte) 69, (byte) 49, (byte) 19, (byte) 48, (byte) 17, (byte) 6, (byte) 3, (byte) 85, (byte) 4,
			(byte) 8, (byte) 12, (byte) 10, (byte) 83, (byte) 111, (byte) 109, (byte) 101, (byte) 45, (byte) 83,
			(byte) 116, (byte) 97, (byte) 116, (byte) 101, (byte) 49, (byte) 17, (byte) 48, (byte) 15, (byte) 6,
			(byte) 3, (byte) 85, (byte) 4, (byte) 10, (byte) 12, (byte) 8, (byte) 67, (byte) 101, (byte) 114,
			(byte) 116, (byte) 65, (byte) 117, (byte) 116, (byte) 104, (byte) 49, (byte) 17, (byte) 48, (byte) 15,
			(byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 3, (byte) 12, (byte) 8, (byte) 67, (byte) 101, (byte) 114,
			(byte) 116, (byte) 65, (byte) 117, (byte) 116, (byte) 104, (byte) 48, (byte) 92, (byte) 48, (byte) 13,
			(byte) 6, (byte) 9, (byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1,
			(byte) 1, (byte) 1, (byte) 5, (byte) 0, (byte) 3, (byte) 75, (byte) 0, (byte) 48, (byte) 72, (byte) 2,
			(byte) 65, (byte) 0, (byte) -81, (byte) -118, (byte) -116, (byte) 28, (byte) 68, (byte) -91, (byte) -115,
			(byte) 18, (byte) 104, (byte) 21, (byte) 18, (byte) -81, (byte) 116, (byte) -39, (byte) 84, (byte) 58,
			(byte) -24, (byte) 36, (byte) -53, (byte) 35, (byte) 2, (byte) 31, (byte) -49, (byte) -29, (byte) -104,
			(byte) 28, (byte) -58, (byte) -120, (byte) 59, (byte) -127, (byte) -3, (byte) -75, (byte) 118, (byte) 126,
			(byte) -24, (byte) 67, (byte) -11, (byte) 31, (byte) -13, (byte) -8, (byte) 119, (byte) 67, (byte) -114,
			(byte) 106, (byte) -114, (byte) 84, (byte) 11, (byte) -77, (byte) 5, (byte) -116, (byte) -67, (byte) 126,
			(byte) -4, (byte) -76, (byte) 125, (byte) -28, (byte) -128, (byte) -32, (byte) -81, (byte) -54, (byte) 81,
			(byte) -46, (byte) 40, (byte) -17, (byte) 2, (byte) 3, (byte) 1, (byte) 0, (byte) 1, (byte) -93, (byte) 80,
			(byte) 48, (byte) 78, (byte) 48, (byte) 29, (byte) 6, (byte) 3, (byte) 85, (byte) 29, (byte) 14, (byte) 4,
			(byte) 22, (byte) 4, (byte) 20, (byte) -26, (byte) 45, (byte) 119, (byte) 26, (byte) -45, (byte) -52,
			(byte) -1, (byte) -54, (byte) 104, (byte) 103, (byte) -92, (byte) 4, (byte) -85, (byte) 68, (byte) -111,
			(byte) -65, (byte) 87, (byte) -23, (byte) -55, (byte) 61, (byte) 48, (byte) 31, (byte) 6, (byte) 3,
			(byte) 85, (byte) 29, (byte) 35, (byte) 4, (byte) 24, (byte) 48, (byte) 22, (byte) -128, (byte) 20,
			(byte) -26, (byte) 45, (byte) 119, (byte) 26, (byte) -45, (byte) -52, (byte) -1, (byte) -54, (byte) 104,
			(byte) 103, (byte) -92, (byte) 4, (byte) -85, (byte) 68, (byte) -111, (byte) -65, (byte) 87, (byte) -23,
			(byte) -55, (byte) 61, (byte) 48, (byte) 12, (byte) 6, (byte) 3, (byte) 85, (byte) 29, (byte) 19, (byte) 4,
			(byte) 5, (byte) 48, (byte) 3, (byte) 1, (byte) 1, (byte) -1, (byte) 48, (byte) 13, (byte) 6, (byte) 9,
			(byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 11,
			(byte) 5, (byte) 0, (byte) 3, (byte) 65, (byte) 0, (byte) 33, (byte) 75, (byte) 28, (byte) -22, (byte) -58,
			(byte) 81, (byte) -78, (byte) -99, (byte) -3, (byte) -102, (byte) 0, (byte) 84, (byte) 76, (byte) -83,
			(byte) 51, (byte) -67, (byte) -31, (byte) -51, (byte) 107, (byte) 102, (byte) 49, (byte) 1, (byte) 124,
			(byte) 0, (byte) 14, (byte) 8, (byte) 120, (byte) -80, (byte) 117, (byte) 15, (byte) 32, (byte) -47,
			(byte) -65, (byte) -89, (byte) 18, (byte) -34, (byte) 124, (byte) 47, (byte) 114, (byte) -86, (byte) -104,
			(byte) -21, (byte) -79, (byte) 13, (byte) -29, (byte) -93, (byte) -99, (byte) 61, (byte) 17, (byte) 71,
			(byte) 104, (byte) 75, (byte) 116, (byte) 61, (byte) 94, (byte) 125, (byte) 71, (byte) 124, (byte) 5,
			(byte) -87, (byte) -104, (byte) -51, (byte) -69, (byte) -35 };

	// private SSLServerSocketFactory sslServerSocketFactory;

	private SecretKey Ks;

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

		/*** STAP 1 ***/
		System.out.println("Sending Time..");
		boolean isValid = isValid();
		System.out.println("revalidation needed: " + !isValid);
		System.out.println("Complete! \n");

		if (!isValid) {
			System.out.println("Sending Revalidation..");
			sendNewTime(fetchNewTime());
			System.out.println("Complete! \n");
		}

		// Nu connectie opzetten met SP
		SSLConnectionServiceProvider sslCon = new SSLConnectionServiceProvider(this, connection);
		sslCon.connect();
	}

	@FXML
	public void initialize() {
	}

	private void startSimulator() {
		/* Simulation: */
		this.connection = new SimulatedConnection();

		CommandAPDU a;
		ResponseAPDU r;

		try {

			this.connection.connect();

			// 0. create applet (only for simulator!!!)
			a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,
					new byte[] { (byte) 0xa0, 0x00, 0x00, 0x00, 0x62, 0x03, 0x01, 0x08, 0x01 }, 0x7f);
			r = this.connection.transmit(a);
			System.out.println(r);
			if (r.getSW() != 0x9000)
				throw new Exception("select installer applet failed");

			a = new CommandAPDU(0x80, 0xB8, 0x00, 0x00,
					new byte[] { 0xb, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00, 0x00 }, 0x7f);
			r = this.connection.transmit(a);
			System.out.println(r);
			if (r.getSW() != 0x9000)
				throw new Exception("Applet creation failed");

			// 1. Select applet (not required on a real card, applet is selected
			// by default)
			a = new CommandAPDU(0x00, 0xa4, 0x04, 0x00,
					new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x00 }, 0x7f);
			r = this.connection.transmit(a);
			System.out.println(r);
			if (r.getSW() != 0x9000)
				throw new Exception("Applet selection failed");

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
			} else if (r.getSW() == KAPPA) {
				addText("SIGNATURE VALID");
				System.out.println("Signature was valid! Time was updated on card.");
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

	public byte[] authenticateServiceProvider(byte[] cert) {
		CommandAPDU a;
		ResponseAPDU r;

		/** send cert part 1 to JC **/
		try {
			byte[] send = null;
			if (cert.length > 250) {
				send = new byte[250];
				for (int i = 0; i < 250; i++) {
					send[i] = cert[i];
				}
			} else {
				System.out.println("Printing size of certificate " + cert.length);
				send = new byte[cert.length];
				for (int i = 0; i < cert.length; i++) {
					send[i] = cert[i];
				}
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

			/** FETCH SYMMETRIC KEY **/
			a = new CommandAPDU(IDENTITY_CARD_CLA, GET_KEY_INS, 0x00, 0x00, 0xff);
			r = connection.transmit(a);

			if (r.getSW() != 0x9000)
				throw new Exception("Exception on the card: " + Integer.toHexString(r.getSW()));

			byte[] inc = r.getData();
			System.out.println("\tPayload SYMMETRIC KEY: " + Arrays.toString(inc));

			String mod = bytesToHex(dummyPrivModulus);
			String exp = bytesToHex(dummyPrivExponent);
			RSAPrivateKey secretKey = (RSAPrivateKey) generatePrivateKey(mod, exp);

			byte[] data = slice(inc, 0, 64);
			System.out.println(Arrays.toString(data));

			Cipher asymCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			asymCipher.init(Cipher.DECRYPT_MODE, secretKey);

			byte[] decryptedData = new byte[256];
			asymCipher.doFinal(data, (short) 0, (short) data.length, decryptedData, (short) 0);

			byte[] returnData = cutOffNulls(decryptedData);

			return inc;
			// SecretKey originalKey = new SecretKeySpec(returnData, 0,
			// returnData.length, "DES");
			// Ks = originalKey;
			//
			// /** FETCH Emsg **/
			//
			// CertificateFactory certFac =
			// CertificateFactory.getInstance("X.509");
			// InputStream is = new ByteArrayInputStream(certCA);
			// X509Certificate certCA = (X509Certificate)
			// certFac.generateCertificate(is);
			//
			// byte[] subject = certCA.getSubjectDN().getName().getBytes();
			//
			// a = new CommandAPDU(IDENTITY_CARD_CLA, GET_MSG_INS, subject[0],
			// 0x00, 0xff);
			// r = connection.transmit(a);
			//
			// if (r.getSW() != 0x9000)
			// throw new Exception("Exception on the card: " +
			// Integer.toHexString(r.getSW()));
			//
			// inc = r.getData();
			// System.out.println("\tPayload Emsg: " + Arrays.toString(inc));

		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public byte[] slice(byte[] original, int offset, int end) {
		int length = (int) (end - offset);
		byte[] slice = new byte[length];

		for (int i = offset; i < end; i++) {
			int index = (int) (i - offset);
			slice[index] = original[i];
		}
		return slice;
	}

	// private byte[] fetchCert() {
	// SSLConnectionServiceProvider c = new SSLConnectionServiceProvider(this,
	// connection);
	// return c.fetchCert(/** hier waarde in meegeven? **/
	// );
	// }

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

	public static byte[] decryptWithPrivateKey(byte[] data)
			throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Cipher asymCipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");

		asymCipher.init(Cipher.DECRYPT_MODE, Keys.getMyPrivateRSAKey());
		return asymCipher.doFinal(data);
	}

	public static byte[] encryptWithPublicKeySC(byte[] data)
			throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
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

	private byte[] cutOffNulls(byte[] data) {
		short length = (short) data.length;
		for (short i = length; i > 0; i--) {
			byte kappa = data[(short) (i - 1)];
			if (kappa != (byte) 0) {
				length = (short) (i);
				break;
			}
		}

		byte[] cleanedData = new byte[length];
		for (int i = 0; i < length; i++) {
			cleanedData[i] = data[i];
		}

		return cleanedData;
	}

	public static String bytesToHex(byte[] in) {
		final StringBuilder builder = new StringBuilder();
		for (byte b : in) {
			builder.append(String.format("%02x", b));
		}
		return builder.toString();
	}

	public static PrivateKey generatePrivateKey(String mod, String exp)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(new BigInteger(mod, 16), new BigInteger(exp, 16));
		KeyFactory fact = KeyFactory.getInstance("RSA");
		PrivateKey privKey = fact.generatePrivate(keySpec);
		return privKey;
	}

	private static String decrypt(RSAPrivateKey privatekey, byte[] buffer) {

		try {
			Cipher decrypt = Cipher.getInstance("RSA/ECB/PKCS1Padding");
			decrypt.init(Cipher.DECRYPT_MODE, privatekey);
			String decryptedMessage = new String(decrypt.doFinal(buffer), StandardCharsets.UTF_8);

			return decryptedMessage;
		} catch (Exception e) {
			e.printStackTrace();
		}
		return null;
	}

	public static byte[] decryptWithPrivateKey(RSAPrivateKey privatekey, byte[] data)
			throws NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException,
			InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		Cipher asymCipher = Cipher.getInstance("RSA/None/PKCS1Padding", "BC");

		asymCipher.init(Cipher.DECRYPT_MODE, privatekey);
		return asymCipher.doFinal(data);
	}

}
