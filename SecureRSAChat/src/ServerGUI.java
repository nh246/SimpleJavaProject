import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PublicKey;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import java.sql.Connection;
import java.sql.Statement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.DriverManager;

import javax.crypto.SecretKey;

public class ServerGUI extends JFrame {
    private JTextArea chatArea;
    private JTextField messageField;
    private ConcurrentHashMap<Socket, ObjectOutputStream> clients = new ConcurrentHashMap<>();
    private ExecutorService executor = Executors.newFixedThreadPool(10);

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

        loadChatHistory();

        startServer();
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

    private void startServer() {
        new Thread(() -> {
            try (ServerSocket serverSocket = new ServerSocket(5000)) {
                chatArea.append("Server started. Waiting for clients...\n");
                while (true) {
                    Socket socket = serverSocket.accept();
                    executor.execute(new ClientHandler(socket));
                }
            } catch (Exception e) {
                chatArea.append("Error: " + e.getMessage() + "\n");
            }
        }).start();
    }

    private class ClientHandler implements Runnable {
        private Socket socket;
        private ObjectOutputStream output;
        private PublicKey clientPublicKey;
        private String username;

        public ClientHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try {
                output = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
                RSAUtil.generateRSAKeyPair();
                output.writeObject(RSAUtil.getPublicKey());
                clientPublicKey = (PublicKey) input.readObject();
                username = (String) input.readObject();
                chatArea.append(username + " connected!\n");
                clients.put(socket, output);

                SecretKey aesKey = RSAUtil.generateAESKey();
                String encryptedAESKey = RSAUtil.encryptAESKey(aesKey, clientPublicKey);
                output.writeObject(encryptedAESKey);

                while (true) {
                    String encryptedMessage = (String) input.readObject();
                    String message = RSAUtil.decryptWithAES(encryptedMessage, aesKey);
                    chatArea.append(username + ": " + message + "\n");
                    chatArea.setCaretPosition(chatArea.getDocument().getLength());
                    ChatLogger.logMessage(username + ": " + message);
                    broadcastMessage(username + ": " + message, socket);
                }
            } catch (Exception e) {
                chatArea.append(username + " disconnected: " + e.getMessage() + "\n");
                clients.remove(socket);
            }
        }

        private void broadcastMessage(String message, Socket excludeSocket) {
            for (Socket clientSocket : clients.keySet()) {
                if (!clientSocket.equals(excludeSocket)) {
                    try {
                        ObjectOutputStream clientOutput = clients.get(clientSocket);
                        SecretKey aesKey = RSAUtil.generateAESKey();
                        clientOutput.writeObject(RSAUtil.encryptWithAES(message, aesKey));
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                }
            }
        }
    }

    private void sendMessage() {
        try {
            String message = messageField.getText();
            if (!message.isEmpty()) {
                for (ObjectOutputStream clientOutput : clients.values()) {
                    SecretKey aesKey = RSAUtil.generateAESKey();
                    clientOutput.writeObject(RSAUtil.encryptWithAES("Server: " + message, aesKey));
                }
                chatArea.append("Server: " + message + "\n");
                chatArea.setCaretPosition(chatArea.getDocument().getLength());
                ChatLogger.logMessage("Server: " + message);
                messageField.setText("");
                JOptionPane.showMessageDialog(this, "Message sent: " + message, "Notification", JOptionPane.INFORMATION_MESSAGE);
                Toolkit.getDefaultToolkit().beep();
            }
        } catch (Exception e) {
            chatArea.append("Error sending message: " + e.getMessage() + "\n");
        }
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new ServerGUI().setVisible(true));
    }
}