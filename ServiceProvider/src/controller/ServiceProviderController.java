package controller;

import javafx.event.ActionEvent;
import javafx.fxml.FXML;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.TextArea;
import javafx.scene.layout.HBox;

public class ServiceProviderController {

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
		String submit = "Selected: " + name + "," + adress + "," + foto + "," + age + "," + country + "," + birthday
				+ " for " + output;
		addText(submit);
	}

	@FXML
	public void initialize() {
		providerCombo.getItems().addAll("Overheid 1", "Overheid 2", "Sociaal Netwerk 1", "Sociaal Netwerk 2",
				"Default 1", "Default 2", "Keuze 1", "Keuze 2");
		providerCombo.getSelectionModel().selectFirst();
	}

	public void addText(String text) {
		communicationArea.appendText(text+"\n");
	}

}
