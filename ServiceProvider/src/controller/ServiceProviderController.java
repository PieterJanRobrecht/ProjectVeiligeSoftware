package controller;

import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.bouncycastle.openssl.PEMReader;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TextArea;
import javafx.scene.layout.HBox;
import ssl.ServiceProviderServer;

public class ServiceProviderController {
	ServiceProviderServer sps;

	@FXML
	private CheckBox adressCheck;

	@FXML
	private CheckBox fotoCheck;

	@FXML
	private TextArea communicationArea;

	@FXML
	private HBox submitButton;

	@FXML
	private ComboBox<String> providerCombo;

	@FXML
	private CheckBox nameCheck;

	@FXML
	private CheckBox ageCheck;

	@FXML
	private CheckBox countryCheck;

	@FXML
	private CheckBox genderCheck;

	@FXML
	private CheckBox birthDateCheck;

	private Thread serverThread;

	@FXML
	void submitSettings(ActionEvent event) {
		boolean name = nameCheck.selectedProperty().getValue();
		boolean adress = adressCheck.selectedProperty().getValue();
		boolean foto = fotoCheck.selectedProperty().getValue();
		boolean age = ageCheck.selectedProperty().getValue();
		boolean country = countryCheck.selectedProperty().getValue();
		boolean gender = genderCheck.selectedProperty().getValue();
		boolean birthday = birthDateCheck.selectedProperty().getValue();
		String output = providerCombo.getSelectionModel().getSelectedItem().toString();

		try {
			X509Certificate cert = getCertificate(output);
		} catch (Exception e) {
			e.printStackTrace();
		}

		String submit = "Selected: " + name + "," + adress + "," + foto + "," + age + "," + country + "," + birthday + " for " + output;
		addText(submit);

		sps.setTask("1");
	}

	private X509Certificate getCertificate(String output) throws CertificateException, FileNotFoundException {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		FileReader fr = null;
		String fileName = new String();
		// Alle paswoorden zijn gelijk aan password
		switch (output) {
		case "Overheid 1":
			addText("Overheid 1 werd geselecteerd \n\t Certificaat wordt opgehaald");
			fileName = "../Certificaten2/gov1.crt";
			break;
		case "Overheid 2":
			addText("Overheid 2 werd geselecteerd \n\t Certificaat wordt opgehaald");
			fileName = "../Certificaten2/gov2.crt";
			break;
		case "Sociaal Netwerk 1":
			addText("Sociaal Netwerk 1 werd geselecteerd \n\t Certificaat wordt opgehaald");
			fileName = "../Certificaten2/soc1.crt";
			break;
		case "Sociaal Netwerk 2":
			addText("Sociaal Netwerk 1 werd geselecteerd \n\t Certificaat wordt opgehaald");
			fileName = "../Certificaten2/soc2.crt";
			break;
		case "Default 1":
			addText("Default 1 werd geselecteerd \n\t Certificaat wordt opgehaald");
			fileName = "../Certificaten2/def1.crt";
			break;
		case "Default 2":
			addText("Default 1 werd geselecteerd \n\t Certificaat wordt opgehaald");
			fileName = "../Certificaten2/def2.crt";
			break;
		case "Keuze 1":
			addText("Keuze 1 werd geselecteerd \n\t Certificaat wordt opgehaald");
			fileName = "../Certificaten2/oth1.crt";
			break;
		case "Keuze 2":
			addText("Keuze 1 werd geselecteerd \n\t Certificaat wordt opgehaald");
			fileName = "../Certificaten2/oth2.crt";
			break;
		default:
			break;
		}
		fr = new FileReader(fileName);
		PEMReader pemReader = new PEMReader(fr);
		X509Certificate cert = null;
		try {
			cert = (X509Certificate) pemReader.readObject();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return cert;
	}

	@FXML
	public void initialize() {
		providerCombo.getItems().addAll("Overheid 1", "Overheid 2", "Sociaal Netwerk 1", "Sociaal Netwerk 2", "Default 1", "Default 2", "Keuze 1", "Keuze 2");
		providerCombo.getSelectionModel().selectFirst();

		sps = new ServiceProviderServer();

		Thread thread = new Thread(sps);
		thread.start();

		this.setServerThread(thread);

		// scm = new SSLConnectionMiddleware();
	}

	public void addText(String text) {
		communicationArea.appendText(text + "\n");
	}

	public Thread getServerThread() {
		return serverThread;
	}

	public void setServerThread(Thread serverThread) {
		this.serverThread = serverThread;
	}
}
