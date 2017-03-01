package controller;

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
	private final static short SW_VERIFICATION_FAILED = 0x6300;
	private final static short SW_PIN_VERIFICATION_REQUIRED = 0x6301;

	@FXML
	private TextArea communicationArea;

	private Connection connection;

	@FXML
	void login(ActionEvent event) {
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
			addText(a.toString());
			r = connection.transmit(a);
			addText(r.toString());

			System.out.println(r);
			if (r.getSW() == SW_VERIFICATION_FAILED){
				addText("PIN INVALID");
				throw new Exception("PIN INVALID");
			}
			else if (r.getSW() != 0x9000)
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
			// TODO Auto-generated catch block
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

}
