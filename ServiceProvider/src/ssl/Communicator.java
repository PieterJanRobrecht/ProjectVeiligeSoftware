package ssl;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public abstract class Communicator {
	int messageLength = 100;
    byte[] data = new byte[messageLength];
    int bytesLeft,
        bytesExpected,
        chunkReceived;

    protected void send(String message, OutputStream outputStream) throws IOException {
        if (message.length() > messageLength)
            throw new IndexOutOfBoundsException("Message length > 100.");

        char[] messageArray = message.toCharArray();

        for (int i = 0; i < message.length(); i++) {
            data[i] = (byte) messageArray[i];
        }

        for (int i = message.length(); i < messageLength; i++) {
            data[i] = 32;
        }

        outputStream.write(data);
    }

    protected String receive(InputStream inputStream) throws IOException {
        bytesLeft = bytesExpected = messageLength;

        while (bytesLeft > 0) {
            chunkReceived = inputStream.read(data, bytesExpected - bytesLeft, bytesLeft);
            if (chunkReceived == -1) {
                throw new IOException("Datastream closed.");
            } else {
                bytesLeft -= chunkReceived;
            }
        }

        return new String(data).trim();
    }
}