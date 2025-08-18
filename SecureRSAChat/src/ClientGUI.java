import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.Socket;
import java.security.PublicKey;
import java.sql.*;

import javax.crypto.SecretKey;

public class ClientGUI extends JFrame {
    private JTextArea chatArea;
    private JTextField messageField;
    private ObjectOutputStream output;
    private ObjectInputStream input;
    private PublicKey serverPublicKey;
    private SecretKey aesKey;
    private String username;
    private String serverAddress;
    private Socket socket;

    public ClientGUI() {
        super("Secure Chat Client");
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE); // Changed to allow new instances
        setSize(400, 300);
        setLocationRelativeTo(null);

        chatArea = new JTextArea();
        chatArea.setEditable(false);
        chatArea.setBackground(Color.LIGHT_GRAY);
        JScrollPane scrollPane = new JScrollPane(chatArea);
        messageField = new JTextField();
        JButton sendButton = new JButton("Send");
        JButton logoutButton = new JButton("Logout");

        setLayout(new BorderLayout());
        add(scrollPane, BorderLayout.CENTER);
        JPanel bottomPanel = new JPanel(new BorderLayout());
        bottomPanel.add(messageField, BorderLayout.CENTER);
        JPanel buttonPanel = new JPanel(new FlowLayout());
        buttonPanel.add(sendButton);
        buttonPanel.add(logoutButton);
        bottomPanel.add(buttonPanel, BorderLayout.EAST);
        add(bottomPanel, BorderLayout.SOUTH);

        AuthDialog authDialog = new AuthDialog(this);
        authDialog.setVisible(true);
        if (!authDialog.isAuthenticated()) {
            JOptionPane.showMessageDialog(this, "Authentication Failed!", "Error", JOptionPane.ERROR_MESSAGE);
            System.exit(0);
        }

        username = JOptionPane.showInputDialog(this, "Enter your username:", "User1");
        serverAddress = JOptionPane.showInputDialog(this, "Enter Server IP Address:", "localhost");
        if (serverAddress == null || serverAddress.trim().isEmpty()) {
            System.exit(0);
        }

        sendButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                sendMessage();
            }
        });

        logoutButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                logout();
            }
        });

        loadChatHistory();

        startClient();
    }

    private void loadChatHistory() {
        String sql = "SELECT timestamp, message FROM logs ORDER BY id DESC LIMIT 50";
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/chat_db?useSSL=false&allowPublicKeyRetrieval=true", "chat_user", "password123");
             Statement stmt = conn.createStatement()) {
            ResultSet rs = stmt.executeQuery(sql);
            System.out.println("Loading chat history...");
            while (rs.next()) {
                final String log = "[" + rs.getString("timestamp") + "] " + rs.getString("message") + "\n";
                SwingUtilities.invokeLater(() -> chatArea.append(log));
            }
            System.out.println("Chat history loaded successfully.");
        } catch (SQLException e) {
            System.err.println("Error loading chat history: " + e.getMessage());
            SwingUtilities.invokeLater(() -> chatArea.append("Error loading chat history: " + e.getMessage() + "\n"));
        }
    }

    private void startClient() {
        new Thread(() -> {
            try {
                socket = new Socket(serverAddress, 5000);
                chatArea.append("Connected to server!\n");

                output = new ObjectOutputStream(socket.getOutputStream());
                input = new ObjectInputStream(socket.getInputStream());

                serverPublicKey = (PublicKey) input.readObject();
                RSAUtil.generateRSAKeyPair();
                output.writeObject(RSAUtil.getPublicKey());
                output.writeObject(username);

                String encryptedAESKey = (String) input.readObject();
                aesKey = RSAUtil.decryptAESKey(encryptedAESKey, RSAUtil.getPrivateKey());

                while (true) {
                    String encryptedMessage = (String) input.readObject();
                    String message = RSAUtil.decryptWithAES(encryptedMessage, aesKey);
                    chatArea.append(message + "\n");
                    chatArea.setCaretPosition(chatArea.getDocument().getLength());
                    ChatLogger.logMessage(message);
                    JOptionPane.showMessageDialog(this, "New message: " + message, "Notification", JOptionPane.INFORMATION_MESSAGE);
                    Toolkit.getDefaultToolkit().beep();
                }
            } catch (Exception e) {
                chatArea.append("Error: " + e.getMessage() + "\n");
                if (socket != null && !socket.isClosed()) {
                    try {
                        socket.close();
                    } catch (IOException ex) {
                        chatArea.append("Error closing socket: " + ex.getMessage() + "\n");
                    }
                }
            }
        }).start();
    }

    private void sendMessage() {
        try {
            String message = messageField.getText();
            if (!message.isEmpty() && aesKey != null) {
                String encryptedMessage = RSAUtil.encryptWithAES(username + ": " + message, aesKey);
                output.writeObject(encryptedMessage);
                chatArea.append("Me: " + message + "\n");
                chatArea.setCaretPosition(chatArea.getDocument().getLength());
                ChatLogger.logMessage("Me: " + message);
                messageField.setText("");
            } else {
                chatArea.append("Error: Message or AES key is empty!\n");
            }
        } catch (Exception e) {
            chatArea.append("Error sending message: " + e.getMessage() + "\n");
        }
    }

    private void logout() {
        try {
            if (socket != null && !socket.isClosed()) {
                output.writeObject("LOGOUT"); // Notify server (optional, server ignores this for now)
                socket.close();
                chatArea.append("Logged out. You can close this window and start a new session.\n");
                output = null;
                input = null;
                aesKey = null;
                // Do not dispose immediately; let user close manually or via window close
            }
        } catch (IOException e) {
            chatArea.append("Error during logout: " + e.getMessage() + "\n");
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new ClientGUI().setVisible(true));
    }
}