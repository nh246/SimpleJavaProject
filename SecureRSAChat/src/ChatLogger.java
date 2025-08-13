import java.io.BufferedWriter;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;

public class ChatLogger {
    private static final String LOG_FILE = "chat_log.txt";

    public static void logMessage(String message) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(LOG_FILE, true))) {
            String timestamp = LocalDateTime.now().toString();
            writer.write("[" + timestamp + "] " + message + "\n");
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}