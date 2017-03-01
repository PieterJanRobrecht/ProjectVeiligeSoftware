package main;

import java.io.IOException;

import controller.ServiceProviderController;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;

public class ServiceProviderMain extends Application {

	public static void main(String[] args) {
		launch(args);
	}

	public void start(Stage primaryStage) {
		try {
			// Laden van de fxml file waarin alle gui elementen zitten
			FXMLLoader loader = new FXMLLoader();
			Parent root = FXMLLoader.load(getClass().getResource("../ServiceProviderGui.fxml"));

			// Setten van enkele elementen van het hoofdscherm
			primaryStage.setTitle("Service Provider");
			primaryStage.setScene(new Scene(root));
			primaryStage.show();

			// Ophalen van de controller horende bij de view klasse
			ServiceProviderController serviceProviderController = loader.<ServiceProviderController>getController();
			assert (serviceProviderController != null);

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

}
