package ssl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.LinkedBlockingQueue;

import javax.net.ssl.SSLSocket;

public class HandlingThread implements Runnable {
	SSLSocket sslSocket;
	final BlockingQueue<String> queue;
	
	public HandlingThread(SSLSocket sslSocket2, BlockingQueue<String> queue2) {
		sslSocket = sslSocket2;
		queue = queue2;
	}

	public void run() {
		while(true){
			try {
				String message = queue.take();
				
				switch (message) {
				case "AuthSP":
					authenticateServiceProvider();
					break;
				case "AuthCard":
					authenticateCard();
					break;
				default:
					break;
				}
			} catch (InterruptedException | IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	/*** STAP 3 
	 * @throws IOException ***/
	private void authenticateCard() throws IOException {
		// TODO Auto-generated method stub
		System.out.println("Authenticating Card");
		InputStream inputStream = sslSocket.getInputStream();
		OutputStream outputStream = sslSocket.getOutputStream();
	}

	/*** STAP 2 
	 * @throws IOException ***/
	private void authenticateServiceProvider() throws IOException {
		// TODO Auto-generated method stub
		System.out.println("Authenticating Service Provider");
		InputStream inputStream = sslSocket.getInputStream();
		OutputStream outputStream = sslSocket.getOutputStream();
	}
}
