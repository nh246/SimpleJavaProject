import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class AuthDialog extends JDialog {
    private JPasswordField passwordField;
    private boolean authenticated = false;
    private static final String CORRECT_PASSWORD = "1234";

    public AuthDialog(Frame parent) {
        super(parent, "Authentication", true);
        setSize(300, 150);
        setLocationRelativeTo(parent);
        setLayout(new GridLayout(2, 2, 10, 10));

        JLabel label = new JLabel("Enter Password:");
        passwordField = new JPasswordField();
        JButton submitButton = new JButton("Submit");

        submitButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String password = new String(passwordField.getPassword());
                if (password.equals(CORRECT_PASSWORD)) {
                    authenticated = true;
                    dispose();
                } else {
                    JOptionPane.showMessageDialog(AuthDialog.this, "Incorrect Password!", "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        add(label);
        add(passwordField);
        add(new JLabel());
        add(submitButton);
    }

    public boolean isAuthenticated() {
        return authenticated;
    }
}