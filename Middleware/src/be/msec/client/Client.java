package be.msec.client;

import controller.MiddlewareController;
import javafx.application.Application;
import javafx.fxml.FXMLLoader;
import javafx.scene.Parent;
import javafx.scene.Scene;
import javafx.stage.Stage;
import ssl.MiddlewareServer;

import java.io.IOException;

public class Client extends Application {
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
			
			MiddlewareServer mws = new MiddlewareServer(middlewareController);
	        Thread thread = new Thread(mws);
	        thread.start();

		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	/**
	 * @param args
	 */
	public static void main(String[] args) throws Exception {
		launch(args);
		// Schrijf code in de middlewareController -> login functie
	}

}
