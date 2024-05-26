<?php
session_start();

if (isset($_POST['login'])) {

  // Connect to the database (**Consider using a prepared statement for connection details as well**)
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
  $stmt = $mysqli->prepare("SELECT id, password FROM users WHERE username = ?");
  $stmt->bind_param("s", $username);

  // Get the form data (**Escape user input before storing in variables**)
  $username = $mysqli->real_escape_string($_POST['username']);
  $password = $_POST['password'];

  // Execute the SQL statement
  $stmt->execute();
  $stmt->store_result();

  // Check if the user exists
  if ($stmt->num_rows > 0) {

    // Bind the result to variables
    $stmt->bind_result($id, $hashed_password);

    // Fetch the result
    $stmt->fetch();

    // Verify the password securely (**Avoid timing attacks**)
    if (password_verify($password, $hashed_password)) {
      // Use a constant-time comparison to avoid timing attacks
      $isPasswordValid = hash_equals($hashed_password, password_hash($password, PASSWORD_DEFAULT));
      if ($isPasswordValid) {

        // Set session variables securely (**Consider using a session identifier that is unpredictable and not based on user input**)
        $_SESSION['loggedin'] = true;
        // Generate a new, unique session ID (corrected line)
        $_SESSION['session_id'] = uniqid();
        $_SESSION['id'] = $id;
        $_SESSION['username'] = $username;

        // Redirect to the user's dashboard
        header("Location: dashboard.php");
        exit;
      } else {
        echo "Incorrect password!";
      }
    } else {
      echo "Incorrect password!";
    }
  } else {
    echo "User not found!";
  }

  // Close the connection
  $stmt->close();
  $mysqli->close();
}
?>
