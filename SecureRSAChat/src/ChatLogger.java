import java.sql.*;

public class ChatLogger {
    private static final String URL = "jdbc:mysql://localhost:3306/chat_db?useSSL=false&allowPublicKeyRetrieval=true";
    private static final String USER = "chat_user";
    private static final String PASSWORD = "password123";

    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
            System.out.println("MySQL JDBC Driver registered successfully.");
            initializeDatabase();
        } catch (ClassNotFoundException e) {
            System.err.println("MySQL JDBC Driver not found. Add mysql-connector-java to your project. Error: " + e.getMessage());
            e.printStackTrace();
        } catch (Exception e) {
            System.err.println("Error during static initialization: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static void initializeDatabase() {
        try (Connection conn = DriverManager.getConnection(URL, USER, PASSWORD);
             Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS logs (id INT AUTO_INCREMENT PRIMARY KEY, timestamp VARCHAR(50), message TEXT)");
            System.out.println("Database initialized successfully.");
        } catch (SQLException e) {
            System.err.println("Database connection failed: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static void logMessage(String message) {
        String sql = "INSERT INTO logs (timestamp, message) VALUES (?, ?)";
        try (Connection conn = DriverManager.getConnection(URL, USER, PASSWORD);
             PreparedStatement pstmt = conn.prepareStatement(sql)) {
            pstmt.setString(1, java.time.LocalDateTime.now().toString());
            pstmt.setString(2, message);
            pstmt.executeUpdate();
            System.out.println("Message logged successfully: " + message);
        } catch (SQLException e) {
            System.err.println("Failed to log message: " + e.getMessage());
            e.printStackTrace();
        }
    }
}