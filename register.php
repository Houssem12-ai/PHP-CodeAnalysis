<?php
if (isset($_POST['register'])) {

require_once __DIR__ . '/vendor/autoload.php';

$dotenv = new Dotenv\Dotenv(__DIR__);
$dotenv->load();

// Connect to the database (**Consider using a prepared statement for connection details as well**)
$mysqli = new mysqli(
  getenv('DB_HOST'),
  getenv('DB_USERNAME'),
  getenv('DB_PASSWORD'),
  getenv('DB_NAME')
);
  // Check for connection errors
  if ($mysqli->connect_error) {
    die("Connection failed: " . $mysqli->connect_error);
  }

  // Prepare a parameterized SQL statement to prevent SQL injection (**Escape all user input before building the query**)
  $stmt = $mysqli->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
  $stmt->bind_param("sss", $username, $email, $hashed_password);

  // Get the form data (**Escape user input before storing in variables**)
  $username = $mysqli->real_escape_string($_POST['username']);
  $email = $mysqli->real_escape_string($_POST['email']);
  $password = $_POST['password'];

  // Hash the password with a strong algorithm (**Consider using a cost parameter for password_hash()**)
  $hashed_password = password_hash($password, PASSWORD_DEFAULT, [/* Cost parameter */]);

  // Execute the SQL statement
  if ($stmt->execute()) {
    echo "New account created successfully!";
  } else {
    echo "Error: " . $stmt->error;
  }

  // Close the connection
  $stmt->close();
  $mysqli->close();
}
?>

<form action="register.php" method="post">
  <label for="username">Username:</label>
  <input id="username" name="username" required="" type="text" />
  <label for="email">Email:</label>
  <input id="email" name="email" required="" type="email" />
  <label for="password">Password:</label>
  <input id="password" name="password" required="" type="password" />
  <input name="register" type="submit" value="Register" />
</form>