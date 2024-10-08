<?php
session_start();

// Database connection
$host = 'localhost'; // Hostname
$dbname = 'techsiksha'; // Your database name
$username = 'pma'; // Database username
$password = ''; // Database password

$conn = new mysqli($host, $username, $password, $dbname);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Get the input data
$email = $_POST['email'];
$password = $_POST['password'];
$roleInput = $_POST['role']; // User-provided role

// Map the role to an integer
$role = ($roleInput === 'student') ? 1 : (($roleInput === 'expert') ? 2 : null);

if ($role === null) {
    die("Invalid role provided.");
}

// Prepare the SQL statement to fetch the user
$sql = "SELECT * FROM users WHERE email = ? AND role = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("si", $email, $role);

if (!$stmt->execute()) {
    die("SQL Error: " . $stmt->error);
}

$result = $stmt->get_result();

if ($result->num_rows > 0) {
    // User found
    $user = $result->fetch_assoc();

    // Verify the password using password_verify
    if (password_verify($password, $user['password'])) {
        // Password is correct
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_role'] = $user['role'];

        // Redirect based on user type
        if ($role === 1) {
            header("Location: studenthomepage.html");
        } else if ($role === 2) {
            header("Location: experthomepage.html");
        }
        exit();
    } else {
        // Invalid password
        echo "<script>alert('Invalid email or password!'); window.location.href='login.html';</script>";
    }
} else {
    // Invalid login
    echo "<script>alert('No user found with that email and role!'); window.location.href='login.html';</script>";
}

$stmt->close();
$conn->close();
?>
