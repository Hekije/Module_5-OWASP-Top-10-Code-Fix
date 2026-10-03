// OWASP A03:2021 - Injection
// Secure SQL query using PreparedStatement

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;

public class SQLInjectionFix {

    public static ResultSet findUser(
            Connection connection,
            String username) throws SQLException {

        // Use ? instead of concatenating user input
        String query = "SELECT id, username, email " +
                "FROM users " +
                "WHERE username = ?";

        PreparedStatement statement = connection.prepareStatement(query);

        // Treat username as data rather than SQL code
        statement.setString(1, username);

        return statement.executeQuery();
    }
}