package be.msec.smartcard;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.OwnerPIN;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

public class IdentityCard extends Applet {
	private final static byte IDENTITY_CARD_CLA = (byte) 0x80;

	private static final byte VALIDATE_PIN_INS = 0x22;
	private static final byte GET_NAME_INS = 0x24;
	private static final byte GET_SERIAL_INS = 0x26;
	private static final byte SIGN_INS = 0x28;
	private static final byte ASK_LENGTH_INS = 0x30;
	private static final byte GET_CERT_INS = 0x32;

	private static final byte SET_TEMPTIME_INS = 0x40;
	private static final byte VALIDATE_TIME_INS = 0x42;

	private static final byte SEND_SIG_INS = 0x46;
	private static final byte SEND_SIG_TIME_INS = 0x48;

	private static final byte SEND_CERT_INS = 0x41;

	private final static byte PIN_TRY_LIMIT = (byte) 0x03;
	private final static byte PIN_SIZE = (byte) 0x04;

	private final static short SW_VERIFICATION_FAILED = 0x6322;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6323;
	private final static short KAPPA = 0x6337;
	private final static short VERIFY_FAILED = 0x6338;
	private final static short VERIFY_EXCEPTION_THROWN = 0x6339;

	private RSAPublicKey pkMiddleware;
	private RSAPrivateKey secretKey;
	private RSAPublicKey publicKey;

	private byte[] certServiceProvider;

	// 86400 seconden ofwel 24 uur als threshold
	private byte[] threshold = new byte[] { (byte) 0, (byte) 1, (byte) 81, (byte) -128 };
	private byte[] certificate = new byte[] { (byte) 48, (byte) -126, (byte) 1, (byte) -67, (byte) 48, (byte) -126, (byte) 1, (byte) 103, (byte) -96, (byte) 3, (byte) 2, (byte) 1, (byte) 2, (byte) 2, (byte) 5, (byte) 0, (byte) -73, (byte) -43, (byte) 96, (byte) -107, (byte) 48, (byte) 13, (byte) 6, (byte) 9, (byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 5, (byte) 5, (byte) 0, (byte) 48, (byte) 100, (byte) 49, (byte) 11, (byte) 48, (byte) 9, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 6, (byte) 19, (byte) 2, (byte) 66, (byte) 69, (byte) 49, (byte) 13, (byte) 48, (byte) 11, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 7, (byte) 12, (byte) 4, (byte) 71, (byte) 101, (byte) 110, (byte) 116, (byte) 49, (byte) 25, (byte) 48, (byte) 23, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 10, (byte) 12, (byte) 16, (byte) 75, (byte) 97, (byte) 72, (byte) 111, (byte) 32, (byte) 83, (byte) 105, (byte) 110, (byte) 116, (byte) 45, (byte) 76, (byte) 105, (byte) 101, (byte) 118, (byte) 101, (byte) 110, (byte) 49, (byte) 20, (byte) 48, (byte) 18, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 11, (byte) 12, (byte) 11, (byte) 86, (byte) 97, (byte) 107, (byte) 103, (byte) 114, (byte) 111, (byte) 101, (byte) 112, (byte) 32, (byte) 73, (byte) 84, (byte) 49, (byte) 21, (byte) 48, (byte) 19, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 3, (byte) 12, (byte) 12, (byte) 74, (byte) 97, (byte) 110, (byte) 32, (byte) 86, (byte) 111, (byte) 115, (byte) 115, (byte) 97, (byte) 101, (byte) 114, (byte) 116, (byte) 48, (byte) 32, (byte) 23, (byte) 13, (byte) 49, (byte) 48, (byte) 48, (byte) 50, (byte) 50, (byte) 52, (byte) 48, (byte) 57, (byte) 52, (byte) 51, (byte) 48, (byte) 50, (byte) 90, (byte) 24, (byte) 15, (byte) 53, (byte) 49, (byte) 55, (byte) 57, (byte) 48, (byte) 49, (byte) 48, (byte) 57, (byte) 49, (byte) 57, (byte) 50, (byte) 57, (byte) 52, (byte) 50, (byte) 90, (byte) 48, (byte) 100, (byte) 49, (byte) 11, (byte) 48, (byte) 9, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 6, (byte) 19, (byte) 2, (byte) 66, (byte) 69, (byte) 49, (byte) 13, (byte) 48, (byte) 11, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 7, (byte) 12, (byte) 4, (byte) 71, (byte) 101, (byte) 110, (byte) 116, (byte) 49, (byte) 25, (byte) 48, (byte) 23, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 10, (byte) 12, (byte) 16, (byte) 75, (byte) 97, (byte) 72, (byte) 111, (byte) 32, (byte) 83, (byte) 105, (byte) 110, (byte) 116, (byte) 45, (byte) 76, (byte) 105, (byte) 101, (byte) 118, (byte) 101, (byte) 110, (byte) 49, (byte) 20, (byte) 48, (byte) 18, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 11, (byte) 12, (byte) 11, (byte) 86, (byte) 97, (byte) 107, (byte) 103, (byte) 114, (byte) 111, (byte) 101, (byte) 112, (byte) 32, (byte) 73, (byte) 84, (byte) 49, (byte) 21, (byte) 48, (byte) 19, (byte) 6, (byte) 3, (byte) 85, (byte) 4, (byte) 3, (byte) 12, (byte) 12, (byte) 74, (byte) 97, (byte) 110, (byte) 32, (byte) 86, (byte) 111, (byte) 115, (byte) 115, (byte) 97, (byte) 101, (byte) 114, (byte) 116, (byte) 48, (byte) 92, (byte) 48, (byte) 13, (byte) 6, (byte) 9, (byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 1, (byte) 5, (byte) 0, (byte) 3, (byte) 75, (byte) 0, (byte) 48, (byte) 72, (byte) 2, (byte) 65, (byte) 0, (byte) -73, (byte) -43, (byte) 96, (byte) -107, (byte) 82, (byte) 25, (byte) -66, (byte) 34, (byte) 5, (byte) -58, (byte) 75, (byte) -39, (byte) -54, (byte) 43, (byte) 25, (byte) -117, (byte) 80, (byte) -62, (byte) 51, (byte) 19, (byte) 59, (byte) -70, (byte) -100, (byte) 85, (byte) 24, (byte) -57, (byte) 108, (byte) -98, (byte) -2, (byte) 1, (byte) -80, (byte) -39, (byte) 63, (byte) 93, (byte) 112, (byte) 7, (byte) 4, (byte) 18, (byte) -11, (byte) -98, (byte) 17, (byte) 126, (byte) -54, (byte) 27, (byte) -56, (byte) 33, (byte) 77, (byte) -111, (byte) -74, (byte) -78, (byte) 88, (byte) 70, (byte) -22, (byte) -3, (byte) 15, (byte) 16, (byte) 37, (byte) -18, (byte) 92, (byte) 74, (byte) 124, (byte) -107, (byte) -116, (byte) -125, (byte) 2, (byte) 3, (byte) 1, (byte) 0, (byte) 1, (byte) 48, (byte) 13, (byte) 6, (byte) 9, (byte) 42, (byte) -122, (byte) 72, (byte) -122, (byte) -9, (byte) 13, (byte) 1, (byte) 1, (byte) 5, (byte) 5, (byte) 0, (byte) 3, (byte) 65, (byte) 0, (byte) 33, (byte) 97, (byte) 121, (byte) -25, (byte) 43, (byte) -47, (byte) 113, (byte) -104, (byte) -11, (byte) -42, (byte) -46, (byte) -17, (byte) 1, (byte) -38, (byte) 50, (byte) 59, (byte) -63, (byte) -74, (byte) -33, (byte) 90, (byte) 92, (byte) -59, (byte) 99, (byte) -17, (byte) -60, (byte) 17, (byte) 25, (byte) 79, (byte) 68, (byte) 68, (byte) -57, (byte) -8, (byte) -64, (byte) 35, (byte) -19, (byte) -114, (byte) 110, (byte) -116, (byte) 31, (byte) -126, (byte) -24, (byte) 54, (byte) 71, (byte) 82, (byte) -53, (byte) -78, (byte) -84, (byte) -45, (byte) -83, (byte) 87, (byte) 68, (byte) 124, (byte) -1, (byte) -128, (byte) -49, (byte) 124, (byte) 103, (byte) 28, (byte) 56, (byte) -114, (byte) -10, (byte) 97, (byte) -78, (byte) 54 };

	private byte[] serial = new byte[] { (byte) 0x4A, (byte) 0x61, (byte) 0x6e };
	private byte[] name = new byte[] { 0x4A, 0x61, 0x6E, 0x20, 0x56, 0x6F, 0x73, 0x73, 0x61, 0x65, 0x72, 0x74 };
	// private byte[] name = new byte[] { 0x00, 0x00 };

	// eigen
	// private byte[] privModulus = new byte[] { (byte) -73, (byte) -43, (byte)
	// 96, (byte) -107, (byte) 82, (byte) 25, (byte) -66, (byte) 34, (byte) 5,
	// (byte) -58, (byte) 75, (byte) -39, (byte) -54, (byte) 43, (byte) 25,
	// (byte) -117, (byte) 80, (byte) -62, (byte) 51, (byte) 19, (byte) 59,
	// (byte) -70, (byte) -100, (byte) 85, (byte) 24, (byte) -57, (byte) 108,
	// (byte) -98, (byte) -2, (byte) 1, (byte) -80, (byte) -39, (byte) 63,
	// (byte) 93, (byte) 112, (byte) 7, (byte) 4, (byte) 18, (byte) -11, (byte)
	// -98, (byte) 17, (byte) 126, (byte) -54, (byte) 27, (byte) -56, (byte) 33,
	// (byte) 77, (byte) -111, (byte) -74, (byte) -78, (byte) 88, (byte) 70,
	// (byte) -22, (byte) -3, (byte) 15, (byte) 16, (byte) 37, (byte) -18,
	// (byte) 92, (byte) 74, (byte) 124, (byte) -107, (byte) -116, (byte) -125
	// };
	// private byte[] privExponent = new byte[] { (byte) 24, (byte) 75, (byte)
	// 93, (byte) -79, (byte) 62, (byte) 33, (byte) 98, (byte) -52, (byte) 50,
	// (byte) 65, (byte) 43, (byte) -125, (byte) 3, (byte) -63, (byte) -64,
	// (byte) 101, (byte) 117, (byte) -19, (byte) -60, (byte) 60, (byte) 53,
	// (byte) 119, (byte) -118, (byte) -13, (byte) -128, (byte) 11, (byte) -46,
	// (byte) -30, (byte) 12, (byte) 37, (byte) -125, (byte) 14, (byte) 104,
	// (byte) -5, (byte) -15, (byte) -120, (byte) -113, (byte) -49, (byte) -70,
	// (byte) -78, (byte) 114, (byte) 122, (byte) 34, (byte) 114, (byte) -99,
	// (byte) -102, (byte) 43, (byte) -43, (byte) -102, (byte) 71, (byte) 115,
	// (byte) 116, (byte) -105, (byte) -48, (byte) -80, (byte) 109, (byte) 117,
	// (byte) 106, (byte) 88, (byte) 6, (byte) -69, (byte) -42, (byte) -83,
	// (byte) 25 };

	// getjoept.. moet nog aangepast worden aan eigen certificaten
	// gebruik momenteel overal dezelfde :')
	private byte[] dummyPrivExponent = new byte[] { (byte) 0x64, (byte) 0xc2, (byte) 0x8d, (byte) 0xcf, (byte) 0xa1, (byte) 0x1a, (byte) 0x7e, (byte) 0x6a, (byte) 0xc9, (byte) 0x42, (byte) 0xf7, (byte) 0xb6, (byte) 0xad, (byte) 0x86, (byte) 0xdb, (byte) 0xf5, (byte) 0x20, (byte) 0x7c, (byte) 0xcd, (byte) 0x4d, (byte) 0xe9, (byte) 0xfb, (byte) 0x2e, (byte) 0x2b, (byte) 0x99, (byte) 0xfa, (byte) 0x29, (byte) 0x1e, (byte) 0xd9, (byte) 0xbd, (byte) 0xf9, (byte) 0xb2, (byte) 0x77, (byte) 0x9e, (byte) 0x3e, (byte) 0x1a, (byte) 0x60, (byte) 0x67, (byte) 0x8e, (byte) 0xbd, (byte) 0xae, (byte) 0x36, (byte) 0x54, (byte) 0x4a, (byte) 0x11, (byte) 0xc2, (byte) 0x2e, (byte) 0x7c, (byte) 0x9e, (byte) 0xc3, (byte) 0xcb, (byte) 0xba, (byte) 0x65, (byte) 0x2b, (byte) 0xc5, (byte) 0x1b, (byte) 0x6f, (byte) 0x4f, (byte) 0x54, (byte) 0xe1, (byte) 0xff, (byte) 0xc3, (byte) 0x18, (byte) 0x81 };
	private byte[] dummyPrivModulus = new byte[] { (byte) 0x8d, (byte) 0x08, (byte) 0x00, (byte) 0x7e, (byte) 0x39, (byte) 0xb1, (byte) 0x52, (byte) 0x4e, (byte) 0xc8, (byte) 0x90, (byte) 0x90, (byte) 0x37, (byte) 0x93, (byte) 0xd1, (byte) 0xcc, (byte) 0x33, (byte) 0xa8, (byte) 0x8d, (byte) 0xd5, (byte) 0x88, (byte) 0x7d, (byte) 0x5c, (byte) 0xcc, (byte) 0x8a, (byte) 0x26, (byte) 0xaa, (byte) 0x05, (byte) 0x2d, (byte) 0x7c, (byte) 0xed, (byte) 0xd9, (byte) 0xc4, (byte) 0xec, (byte) 0x89, (byte) 0x4e, (byte) 0x27, (byte) 0x85, (byte) 0x9b, (byte) 0x33, (byte) 0x43, (byte) 0x72, (byte) 0xae, (byte) 0xe2, (byte) 0xc8, (byte) 0x4d, (byte) 0x7c, (byte) 0x04, (byte) 0x02, (byte) 0xcd, (byte) 0x46, (byte) 0xf0, (byte) 0x3b, (byte) 0xd8, (byte) 0xa0, (byte) 0xb9, (byte) 0xd1, (byte) 0x9d, (byte) 0x33, (byte) 0x44, (byte) 0xe1, (byte) 0xfa, (byte) 0x0d, (byte) 0xf6, (byte) 0x69 };
	private byte[] dummyPubExponent = new byte[] { (byte) 0x01, (byte) 0x00, (byte) 0x01 };
	private byte[] dummyPubModulus = new byte[] { (byte) 0x8d, (byte) 0x08, (byte) 0x00, (byte) 0x7e, (byte) 0x39, (byte) 0xb1, (byte) 0x52, (byte) 0x4e, (byte) 0xc8, (byte) 0x90, (byte) 0x90, (byte) 0x37, (byte) 0x93, (byte) 0xd1, (byte) 0xcc, (byte) 0x33, (byte) 0xa8, (byte) 0x8d, (byte) 0xd5, (byte) 0x88, (byte) 0x7d, (byte) 0x5c, (byte) 0xcc, (byte) 0x8a, (byte) 0x26, (byte) 0xaa, (byte) 0x05, (byte) 0x2d, (byte) 0x7c, (byte) 0xed, (byte) 0xd9, (byte) 0xc4, (byte) 0xec, (byte) 0x89, (byte) 0x4e, (byte) 0x27, (byte) 0x85, (byte) 0x9b, (byte) 0x33, (byte) 0x43, (byte) 0x72, (byte) 0xae, (byte) 0xe2, (byte) 0xc8, (byte) 0x4d, (byte) 0x7c, (byte) 0x04, (byte) 0x02, (byte) 0xcd, (byte) 0x46, (byte) 0xf0, (byte) 0x3b, (byte) 0xd8, (byte) 0xa0, (byte) 0xb9, (byte) 0xd1, (byte) 0x9d, (byte) 0x33, (byte) 0x44, (byte) 0xe1, (byte) 0xfa, (byte) 0x0d, (byte) 0xf6, (byte) 0x69 };

	private OwnerPIN pin;

	private byte[] lastTime;
	private byte[] tempTime;

	private byte[] tempTimeUpdate;

	private IdentityCard() {
		/* During instantiation of the applet, all objects are created. */
		pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);
		pin.update(new byte[] { 0x01, 0x02, 0x03, 0x04 }, (short) 0, PIN_SIZE);

		// initial time
		lastTime = new byte[] { (byte) 0, (byte) 0, (byte) 0, (byte) 0 };

		/* Build private RSA Key based on dummy */
		short offset = 0;
		short keySizeInBytes = 64;
		short keySizeInBits = (short) (keySizeInBytes * 8);
		secretKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, keySizeInBits, false);
		secretKey.setExponent(dummyPrivExponent, offset, keySizeInBytes);
		secretKey.setModulus(dummyPrivModulus, offset, keySizeInBytes);

		/* Build public RSA Key based on dummy */
		offset = 0;
		keySizeInBytes = 64; // dit aanpassen D:
		keySizeInBits = (short) (keySizeInBytes * 8);
		publicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, keySizeInBits, false);
		publicKey.setExponent(dummyPubExponent, offset, (short) 3);
		publicKey.setModulus(dummyPubModulus, offset, keySizeInBytes);

		/* Build public RSA Key of Middleware */
		offset = 0;
		keySizeInBytes = 64;
		keySizeInBits = (short) (keySizeInBytes * 8);
		pkMiddleware = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, keySizeInBits, false);
		pkMiddleware.setExponent(dummyPubExponent, offset, (short) 3);
		pkMiddleware.setModulus(dummyPubModulus, offset, keySizeInBytes);

		/* This method registers the applet with the JCRE on the card. */
		register();
	}

	/*
	 * This method is called by the JCRE when installing the applet on the card.
	 */
	public static void install(byte bArray[], short bOffset, byte bLength) throws ISOException {
		new IdentityCard();
	}

	/*
	 * If no tries are remaining, the applet refuses selection. The card can,
	 * therefore, no longer be used for identification.
	 */
	public boolean select() {
		if (pin.getTriesRemaining() == 0)
			return false;
		return true;
	}

	/*
	 * This method is called when the applet is selected and an APDU arrives.
	 */
	public void process(APDU apdu) throws ISOException {
		// A reference to the buffer, where the APDU data is stored, is
		// retrieved.
		byte[] buffer = apdu.getBuffer();

		// If the APDU selects the applet, no further processing is required.
		if (this.selectingApplet())
			return;

		// Check whether the indicated class of instructions is compatible with
		// this applet.
		if (buffer[ISO7816.OFFSET_CLA] != IDENTITY_CARD_CLA)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		// A switch statement is used to select a method depending on the
		// instruction
		switch (buffer[ISO7816.OFFSET_INS]) {
		case VALIDATE_PIN_INS:
			validatePIN(apdu);
			break;
		case GET_SERIAL_INS:
			getSerial(apdu);
			break;
		case GET_NAME_INS:
			getName(apdu);
			break;
		case SIGN_INS:
			signSomething(apdu);
			break;
		case ASK_LENGTH_INS:
			askLength(apdu);
			break;
		case GET_CERT_INS:
			askCertificate(apdu);
			break;
		case SET_TEMPTIME_INS:
			setTempTime(apdu);
			break;
		case VALIDATE_TIME_INS:
			validateTime(apdu);
			break;
		case SEND_SIG_INS:
			updateSig(apdu);
			break;
		case SEND_SIG_TIME_INS:
			updateTime(apdu);
			break;
		case SEND_CERT_INS:
			receiveCert(apdu);
			break;
		default:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}

	private boolean compareTime() {
		// Twee tijden van elkaar aftrekken
		byte[] result = new byte[4];
		for (short i = 0; i < 4; i++) {
			result[i] = (byte) (tempTime[i] - lastTime[i]);
		}

		boolean refresh = false;
		// Vergelijken met threshold
		for (short i = 0; i < 4; i++) {
			if (i == 0) {
				if (tempTime[0] != lastTime[0]) {
					refresh = true;
					break;
				}
			} else if (result[i] != (short) threshold[i])
				if (result[i] < (short) threshold[i]) {
					refresh = true;
					break;
				} else {
					refresh = false;
					break;
				}
		}
		return refresh;
	}

	public byte[] slice(byte[] original, short offset, short end) {
		short length = (short) (end - offset);
		byte[] slice = new byte[length];

		for (short i = offset; i < end; i++) {
			short index = (short) (i - offset);
			slice[index] = original[i];
		}
		return slice;
	}

	private void receiveCert(APDU apdu) {
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else {
			byte[] buffer = apdu.getBuffer();

			short teller = (short) (buffer[ISO7816.OFFSET_P1] & (short) 0xFF); // test?

			byte[] incomingData = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);
			short bytesLeft;
			short readCount;
			short offSet = 0x00;

			if (teller == (short) 1) {
				bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
				readCount = apdu.setIncomingAndReceive();
				while (bytesLeft > 0) {
					Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, incomingData, offSet, readCount);
					bytesLeft -= readCount;
					offSet += readCount;
					readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
				}

				certServiceProvider = new byte[(short) incomingData.length];
				Util.arrayCopy(incomingData, (short) 0, certServiceProvider, (short) 0, (short) incomingData.length);
				certServiceProvider = cutOffNulls(certServiceProvider);
			} else if (teller == (short) 2) {
				bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
				readCount = apdu.setIncomingAndReceive();
				while (bytesLeft > 0) {
					Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, incomingData, offSet, readCount);
					bytesLeft -= readCount;
					offSet += readCount;
					readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
				}

				// certServiceProvider = new byte[(short) incomingData.length];
				// Util.arrayCopy(incomingData, (short) 0, certServiceProvider,
				// (short) 0, (short) incomingData.length);
				cutOffNulls(certServiceProvider);
				byte[] temp = new byte[(short) (incomingData.length + certServiceProvider.length)];
				Util.arrayCopy(certServiceProvider, (short) 0, temp, (short) 0, (short) certServiceProvider.length);
				Util.arrayCopy(incomingData, (short) 0, temp, (short) certServiceProvider.length, (short) incomingData.length);

				certServiceProvider = temp;
				certServiceProvider = cutOffNulls(certServiceProvider);
			}
		}
	}

	/*
	 * This method is used to authenticate the owner of the card using a PIN
	 * code.
	 */
	private void validatePIN(APDU apdu) {
		// shizzle in commentaar is om te werken adhv encrypted communication

		// byte[] pinBytesWithNull = receiveBytesEncryptedByMW(apdu);
		// byte[] pinBytes = removeNullBytes(pinBytesWithNull);
		byte[] buffer = apdu.getBuffer();

		// if (pinBytes.length == PIN_SIZE) {
		// if (pin.check(pinBytes, (short) 0, PIN_SIZE) == false)
		// ISOException.throwIt(SW_VERIFICATION_FAILED);
		// } else1515
		// ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if (buffer[ISO7816.OFFSET_LC] == PIN_SIZE) {
			apdu.setIncomingAndReceive();
			if (pin.check(buffer, ISO7816.OFFSET_CDATA, PIN_SIZE) == false)
				ISOException.throwIt(SW_VERIFICATION_FAILED);
		} else
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
	}

	/*
	 * This method checks whether the user is authenticated and sends the serial
	 * number.
	 */
	private void getSerial(APDU apdu) {
		// If the pin is not validated, a response APDU with the
		// 'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else {
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) serial.length);
			apdu.sendBytesLong(serial, (short) 0, (short) serial.length);
		}
	}

	private void updateTime(APDU apdu) {
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else {
			/** TODO: add verifySig en lastValidationTime < time? **/
			byte[] buffer = apdu.getBuffer();
			byte[] time = slice(buffer, ISO7816.OFFSET_CDATA, (short) buffer.length);
			time = slice(time, (short) 0, (short) 4);
			tempTimeUpdate = time;
		}
	}

	private void updateSig(APDU apdu) {
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else {
			/** TODO: add verifySig en lastValidationTime < time? **/
			byte[] buffer = apdu.getBuffer();
			byte[] incomingData = JCSystem.makeTransientByteArray((short) 256, JCSystem.CLEAR_ON_RESET);
			short bytesLeft;
			short readCount;
			short offSet = 0x00;

			bytesLeft = (short) (buffer[ISO7816.OFFSET_LC] & 0x00FF);
			readCount = apdu.setIncomingAndReceive();
			while (bytesLeft > 0) {
				Util.arrayCopyNonAtomic(buffer, ISO7816.OFFSET_CDATA, incomingData, offSet, readCount);
				bytesLeft -= readCount;
				offSet += readCount;
				readCount = apdu.receiveBytes(ISO7816.OFFSET_CDATA);
			}

			//incomingData = cutOffNulls(incomingData);
			byte[] signature = new byte[64];
			for(short i = 0; i < 64; i++) {
				signature[i] = incomingData[i];
			}

			try {
				// boolean verified = verifySignatureForMessage(publicKey, incomingData, tempTimeUpdate);
				// RSAPublicKey pubKey, byte[] dataBuffer, short dataOffset, byte[] signatureBuffer, short signatureOffset) {
				boolean verified = verifyPublic(publicKey, tempTimeUpdate, (short) 0, signature, (short) 0);
				if (verified) {
					lastTime = tempTimeUpdate;
					tempTimeUpdate = null;
					ISOException.throwIt(KAPPA);
				} else {
					ISOException.throwIt(VERIFY_FAILED);
				}
			} catch (Exception e) {
				ISOException.throwIt(VERIFY_EXCEPTION_THROWN);
			}

		}
	}

	private void getName(APDU apdu) {
		// If the pin is not validated, a response APDU with the
		// 'SW_PIN_VERIFICATION_REQUIRED' status word is transmitted.
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else {
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) name.length);
			apdu.sendBytesLong(name, (short) 0, (short) name.length);
		}
	}

	public void signSomething(APDU apdu) {
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else {

			byte[] buffer = apdu.getBuffer();
			byte[] output = new byte[240];
			short siglength = generateSignature(secretKey, buffer, ISO7816.OFFSET_CDATA, apdu.setIncomingAndReceive(), output);

			apdu.setOutgoing();
			apdu.setOutgoingLength(siglength);
			apdu.sendBytesLong(output, (short) 0, (short) siglength);
		}
	}

	public boolean verifySignatureForMessage(RSAPublicKey pubKey, byte[] sig, byte[] message) throws Exception {
		Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		signature.init(pubKey, Signature.MODE_VERIFY);
		return signature.verify(message, (short) 0x80, (short) 4, sig, (short) 0, (short) 0x80);
	}

	public boolean verifyPublic(RSAPublicKey pubKey, byte[] dataBuffer, short dataOffset, byte[] signatureBuffer, short signatureOffset) {
		Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		signature.init(pubKey, Signature.MODE_VERIFY);
		try {
			return signature.verify(dataBuffer, dataOffset, (short) 4, signatureBuffer, signatureOffset, (short) 64);
		} catch (Exception e) {
			return false;
		}
	}

	public short generateSignature(RSAPrivateKey privKey, byte[] input, short offset, short length, byte[] output) {
		Signature signature = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
		signature.init(privKey, Signature.MODE_SIGN);
		short sigLength = signature.sign(input, offset, length, output, (short) 0);
		return sigLength;
	}

	public void setTempTime(APDU apdu) {
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else {
			byte[] buffer = apdu.getBuffer();

			if (tempTime == null) {
				tempTime = new byte[4];

				tempTime[0] = (byte) (buffer[ISO7816.OFFSET_P1] & (short) 0xFF); // test?
				tempTime[1] = (byte) (buffer[ISO7816.OFFSET_P2] & (short) 0xFF); // test?
			} else {
				tempTime[2] = (byte) (buffer[ISO7816.OFFSET_P1] & (short) 0xFF); // test?
				tempTime[3] = (byte) (buffer[ISO7816.OFFSET_P2] & (short) 0xFF); // test?
			}
		}
	}

	public void validateTime(APDU apdu) {
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		// If current - last(buffer) > threshold send 0 else 1
		boolean refresh = compareTime();

		byte[] answer;

		if (refresh) {
			answer = new byte[] { (byte) 0 };
		} else {
			answer = new byte[] { (byte) 1 };
		}

		tempTime = null;

		apdu.setOutgoing();
		apdu.setOutgoingLength((short) answer.length);
		apdu.sendBytesLong(answer, (short) 0, (short) answer.length);
	}

	public void askLength(APDU apdu) {
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else {
			// certificate.length is short --> bv 240
			// byte 128
			// 240 / 128 --> 1 // rest: 112
			// resp[0] = 1 en resp[1] = 112

			byte[] response = new byte[2];
			response[0] = (byte) (certServiceProvider.length / 100);
			response[1] = (byte) (certServiceProvider.length % 100);
			apdu.setOutgoing();
			apdu.setOutgoingLength((short) response.length);
			apdu.sendBytesLong(response, (short) 0, (short) response.length);
		}
	}

	public void askCertificate(APDU apdu) {
		if (!pin.isValidated())
			ISOException.throwIt(SW_PIN_VERIFICATION_REQUIRED);
		else {

			byte[] buffer = apdu.getBuffer();
			byte[] output = new byte[240];

			short teller = (short) (buffer[ISO7816.OFFSET_P1] & (short) 0xFF); // test?

			short hulp = 0;
			short start = (short) (teller * 240);
			short end;
			if ((short) (((short) (teller + 1)) * 240) > (short) certServiceProvider.length) {
				end = (short) certServiceProvider.length;
			} else {
				end = (short) (start + 240);
			}

			for (short i = start; i < end; i++) {
				output[hulp] = certServiceProvider[i];
				hulp++;
			}

			apdu.setOutgoing();
			apdu.setOutgoingLength((short) output.length);
			apdu.sendBytesLong(output, (short) 0, (short) output.length);
		}
	}

	private void sendBytesEncryptedForMW(APDU apdu, byte[] data, short dataLen) {
		Cipher asymCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		asymCipher.init(pkMiddleware, Cipher.MODE_ENCRYPT);
		byte[] encryptedData = new byte[256];

		byte[] dataToEncrypt = new byte[64];

		Util.arrayCopy(data, (short) 0, dataToEncrypt, (short) 0, (short) data.length);

		asymCipher.doFinal(data, (short) 0, (short) data.length, encryptedData, (short) 0);

		apdu.setOutgoing();
		apdu.setOutgoingLength((short) encryptedData.length);
		apdu.sendBytesLong(encryptedData, (short) 0, (short) encryptedData.length);
	}

	private byte[] receiveBytesEncryptedByMW(APDU apdu) {
		byte[] buffer = apdu.getBuffer();
		apdu.setIncomingAndReceive();
		short inc = apdu.getIncomingLength();
		byte[] encryptedData = new byte[inc];
		Util.arrayCopy(buffer, (short) ISO7816.OFFSET_CDATA, encryptedData, (short) 0, inc);

		Cipher asymCipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
		asymCipher.init(secretKey, Cipher.MODE_DECRYPT);

		byte[] decryptedData = new byte[256];
		short length = asymCipher.doFinal(encryptedData, (short) 0, (short) inc, decryptedData, (short) 0);

		byte[] returnData = new byte[length];
		Util.arrayCopy(decryptedData, (short) 0, returnData, (short) 0, length);

		return decryptedData;
	}

	private byte[] cutOffNulls(byte[] data) {
		short length = (short) data.length;
		for (short i = length; i > 0; i--) {
			byte kappa = data[(short) (i - 1)];
			if (kappa != (byte) 0) {
				length = (short) (i - 1);
				break;
			}
		}

		byte[] cleanedData = new byte[length];
		Util.arrayCopy(data, (short) 0, cleanedData, (short) 0, length);

		return cleanedData;
	}
}