package ssl;

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
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}
	
	private void authenticateCard() {
		// TODO Auto-generated method stub
		
	}

	private void authenticateServiceProvider() {
		// TODO Auto-generated method stub
		System.out.println("Authenticating Service Provider");
	}
}
