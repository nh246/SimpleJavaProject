import javax.swing.*;
import java.awt.*;
import java.awt.event.*;

public class AuthDialog extends JDialog {
    private JTextField usernameField;
    private JPasswordField passwordField;
    private boolean authenticated;

    public AuthDialog(JFrame parent) {
        super(parent, "Authentication", true);
        setLayout(new GridLayout(3, 2));
        setSize(300, 150);
        setLocationRelativeTo(parent);

        add(new JLabel("Username:"));
        usernameField = new JTextField();
        add(usernameField);

        add(new JLabel("Password:"));
        passwordField = new JPasswordField();
        add(passwordField);

        JButton loginButton = new JButton("Login");
        loginButton.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                String password = new String(passwordField.getPassword());
                if ("1234".equals(password)) {
                    authenticated = true;
                    dispose();
                } else {
                    JOptionPane.showMessageDialog(AuthDialog.this, "Incorrect password!", "Error", JOptionPane.ERROR_MESSAGE);
                }
            }
        });
        add(loginButton);

        add(new JLabel()); // Empty cell for layout

        setVisible(true);
    }

    public boolean isAuthenticated() {
        return authenticated;
    }
}