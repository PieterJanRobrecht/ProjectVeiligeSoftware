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

    }

}
