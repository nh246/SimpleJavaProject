import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;

public class ServerGUI extends JFrame {
    private JTextArea chatArea;
    private JTextField messageField;
    private ObjectOutputStream output;
    private ObjectInputStream input;
    private PublicKey clientPublicKey;

    public ServerGUI() {
        super("Secure Chat Server");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(400, 300);
        setLocationRelativeTo(null);

        chatArea = new JTextArea();
        chatArea.setEditable(false);
        chatArea.setBackground(Color.LIGHT_GRAY);
        JScrollPane scrollPane = new JScrollPane(chatArea);
        messageField = new JTextField();
        JButton sendButton = new JButton("Send");

        setLayout(new BorderLayout());
        add(scrollPane, BorderLayout.CENTER);
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(messageField, BorderLayout.CENTER);
        bottomPanel.add(sendButton, BorderLayout.EAST);
        add(bottomPanel, BorderLayout.SOUTH);

        AuthDialog authDialog = new AuthDialog(this);
        authDialog.setVisible(true);
        if (!authDialog.isAuthenticated()) {
            JOptionPane.showMessageDialog(this, "Authentication Failed!", "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        }

        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendMessage();
            }
        });

        startServer();
    }

    private void startServer() {
        new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(5000)) {
                chatArea.append("Server started. Waiting for client...\n");
                Socket socket = serverSocket.accept();
                chatArea.append("Client connected!\n");

                output = new ObjectOutputStream(socket.getOutputStream());
                input = new ObjectInputStream(socket.getInputStream());

                RSAUtil.generateKeyPair();
                output.writeObject(RSAUtil.getPublicKey());
                clientPublicKey = (PublicKey) input.readObject();

                while (true) {
                    String encryptedMessage = (String) input.readObject();
                    String message = RSAUtil.decrypt(encryptedMessage);
                    chatArea.append("Client: " + message + "\n");
                    chatArea.setCaretPosition(chatArea.getDocument().getLength()); // Auto-scroll
                    ChatLogger.logMessage("Client: " + message);
                }
            } catch (Exception e) {
                e.printStackTrace();
                chatArea.append("Error: " + e.getMessage() + "\n");
            }
        }).start();
    }

    private void sendMessage() {
        try {
            String message = messageField.getText();
            if (!message.isEmpty()) {
                String encryptedMessage = RSAUtil.encrypt(message, clientPublicKey);
                output.writeObject(encryptedMessage);
                chatArea.append("Server: " + message + "\n");
                chatArea.setCaretPosition(chatArea.getDocument().getLength()); // Auto-scroll
                ChatLogger.logMessage("Server: " + message);
                messageField.setText("");
            }
        } catch (Exception e) {
            e.printStackTrace();
            chatArea.append("Error sending message: " + e.getMessage() + "\n");
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new ServerGUI().setVisible(true));
    }
}