<?php
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Content-Type: application/json');

// Handle preflight requests
$host = getenv('DB_HOST');       // ex: db.onrender.com
$dbname = getenv('DB_NAME');     // nom de la base
$username = getenv('DB_USER');   // utilisateur
$password = getenv('DB_PASSWORD'); // mot de passe
$port = getenv('DB_PORT') ?: 3306; // port par défaut si non défini

try {
    $pdo = new PDO("mysql:host=$host;port=$port;dbname=$dbname;charset=utf8mb4", $username, $password);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (PDOException $e) {
    echo json_encode(['status' => 'error', 'message' => 'Database connection failed: ' . $e->getMessage()]);
    exit();
}


// Get action parameter
$action = $_GET['action'] ?? '';

switch ($action) {
    case 'login':
        handleLogin($pdo);
        break;
    case 'generate_qr':
        handleGenerateQR($pdo);
        break;
    case 'check_attendance':
        handleCheckAttendance($pdo);
        break;
    case 'list_presences':
        handleListPresences($pdo);
        break;
    case 'my_presences':
        handleMyPresences($pdo);
        break;
    case 'getStudent':
        handleGetStudent();
        break;
    case 'getStructure':
        handleGetStructure();
        break;
    default:
        echo json_encode(['status' => 'error', 'message' => 'Invalid action']);
        break;
}

// --------------------
// LOGIN (mot de passe clair)
// --------------------
function handleLogin($pdo) {
    $input = json_decode(file_get_contents('php://input'), true);
    $matricule = $input['matricule'] ?? '';
    $password = $input['password'] ?? '';

    if (empty($matricule) || empty($password)) {
        echo json_encode(['status' => 'error', 'message' => 'Matricule et mot de passe requis']);
        return;
    }

    // Vérifie si utilisateur est enseignant
    $stmt = $pdo->prepare("SELECT id, matricule, nom, password FROM enseignants WHERE matricule = ?");
    $stmt->execute([$matricule]);
    $teacher = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($teacher && $teacher['password'] === $password) {
        unset($teacher['password']);
        $teacher['type'] = 'teacher';
        echo json_encode(['status' => 'success', 'data' => $teacher]);
        return;
    }

    // Vérifie si utilisateur est étudiant
    $stmt = $pdo->prepare("SELECT id, matricule, nom, password FROM etudiants WHERE matricule = ?");
    $stmt->execute([$matricule]);
    $student = $stmt->fetch(PDO::FETCH_ASSOC);

    if ($student && $student['password'] === $password) {
        unset($student['password']);
        $student['type'] = 'student';
        echo json_encode(['status' => 'success', 'data' => $student]);
        return;
    }

    echo json_encode(['status' => 'error', 'message' => 'Matricule ou mot de passe incorrect']);
}

// --------------------
// GENERATE QR
// --------------------
function handleGenerateQR($pdo) {
    $input = json_decode(file_get_contents('php://input'), true);
    $enseignant_id = $input['enseignant_id'] ?? 0;

    if (empty($enseignant_id)) {
        echo json_encode(['status' => 'error', 'message' => 'ID enseignant requis']);
        return;
    }

    $session_id = uniqid('session_', true);
    $token = bin2hex(random_bytes(16));
    $expiration = date('Y-m-d H:i:s', time() + (5 * 60)); // 5 minutes

    try {
        $stmt = $pdo->prepare("INSERT INTO sessions (session_id, enseignant_id, token, expiration) VALUES (?, ?, ?, ?)");
        $stmt->execute([$session_id, $enseignant_id, $token, $expiration]);

        $qr_url = "https://backend-ipressence.onrender.com?action=check_attendance&session_id=$session_id&token=$token";

        echo json_encode([
            'status' => 'success',
            'qr_url' => $qr_url,
            'session_id' => $session_id,
            'expiration' => $expiration
        ]);
    } catch (PDOException $e) {
        echo json_encode(['status' => 'error', 'message' => 'Erreur lors de la création de la session']);
    }
}

// --------------------
// CHECK ATTENDANCE
// --------------------
function handleCheckAttendance($pdo) {
    $input = json_decode(file_get_contents('php://input'), true);
    $matricule = $input['matricule'] ?? '';
    $session_id = $input['session_id'] ?? '';
    $token = $input['token'] ?? '';

    // Si le matricule est vide, rediriger vers le site
    if (empty($matricule)) {
        echo json_encode([
            'status' => 'redirect',
            'url' => 'https://ipressence-m.vercel.app/'
        ]);
        return;
    }

    if (empty($session_id) || empty($token)) {
        echo json_encode(['status' => 'error', 'message' => 'Paramètres manquants']);
        return;
    }

    try {
        $stmt = $pdo->prepare("SELECT * FROM sessions WHERE session_id = ? AND token = ? AND expiration > NOW()");
        $stmt->execute([$session_id, $token]);
        $session = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$session) {
            echo json_encode(['status' => 'error', 'message' => 'Session invalide ou expirée']);
            return;
        }

        $stmt = $pdo->prepare("SELECT id FROM etudiants WHERE matricule = ?");
        $stmt->execute([$matricule]);
        $student = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$student) {
            echo json_encode(['status' => 'error', 'message' => 'Étudiant non trouvé']);
            return;
        }

        $stmt = $pdo->prepare("SELECT id FROM presences WHERE etudiant_id = ? AND session_id = ?");
        $stmt->execute([$student['id'], $session_id]);
        if ($stmt->fetch()) {
            echo json_encode(['status' => 'error', 'message' => 'Présence déjà enregistrée pour cette session']);
            return;
        }

        $stmt = $pdo->prepare("INSERT INTO presences (etudiant_id, session_id, date_heure) VALUES (?, ?, NOW())");
        $stmt->execute([$student['id'], $session_id]);

        echo json_encode(['status' => 'success', 'message' => 'Présence enregistrée avec succès']);
    } catch (PDOException $e) {
        echo json_encode(['status' => 'error', 'message' => 'Erreur lors de l\'enregistrement']);
    }
}


// --------------------
// LIST PRESENCES
// --------------------
function handleListPresences($pdo) {
    $session_id = $_GET['session_id'] ?? '';

    if (empty($session_id)) {
        echo json_encode(['status' => 'error', 'message' => 'Session ID requis']);
        return;
    }

    try {
        $stmt = $pdo->prepare("
            SELECT p.id, e.matricule as etudiant_matricule, e.nom as etudiant_nom, 
                   p.session_id, p.date_heure
            FROM presences p
            JOIN etudiants e ON p.etudiant_id = e.id
            WHERE p.session_id = ?
            ORDER BY p.date_heure DESC
        ");
        $stmt->execute([$session_id]);
        $presences = $stmt->fetchAll(PDO::FETCH_ASSOC);

        echo json_encode(['status' => 'success', 'data' => $presences]);
    } catch (PDOException $e) {
        echo json_encode(['status' => 'error', 'message' => 'Erreur lors du chargement']);
    }
}

// --------------------
// MY PRESENCES
// --------------------
function handleMyPresences($pdo) {
    $matricule = $_GET['matricule'] ?? '';

    if (empty($matricule)) {
        echo json_encode(['status' => 'error', 'message' => 'Matricule requis']);
        return;
    }

    try {
        $stmt = $pdo->prepare("
            SELECT p.id, p.session_id, p.date_heure
            FROM presences p
            JOIN etudiants e ON p.etudiant_id = e.id
            WHERE e.matricule = ?
            ORDER BY p.date_heure DESC
        ");
        $stmt->execute([$matricule]);
        $presences = $stmt->fetchAll(PDO::FETCH_ASSOC);

        echo json_encode(['status' => 'success', 'data' => $presences]);
    } catch (PDOException $e) {
        echo json_encode(['status' => 'error', 'message' => 'Erreur lors du chargement']);
    }
}

// --------------------
// GET STUDENT
// --------------------
function handleGetStudent() {
    $matricule = $_GET['matricule'] ?? '';

    if (empty($matricule)) {
        echo json_encode(['status' => 'error', 'message' => 'Matricule requis']);
        return;
    }

    $url = "https://akhademie.ucbukavu.ac.cd/api/v1/school-students/read-by-matricule?matricule=" . urlencode($matricule);
    $context = stream_context_create(['http' => ['timeout' => 30, 'ignore_errors' => true]]);
    $response = @file_get_contents($url, false, $context);

    if ($response === false) {
        echo json_encode(['status' => 'error', 'message' => 'Erreur de connexion à l\'API UCB']);
        return;
    }

    $data = json_decode($response, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        echo json_encode(['status' => 'error', 'message' => 'Réponse invalide de l\'API UCB']);
        return;
    }

    echo json_encode(['status' => 'success', 'data' => $data]);
}

// --------------------
// GET STRUCTURE
// --------------------
function handleGetStructure() {
    $url = "https://akhademie.ucbukavu.ac.cd/api/v1/school/entity-main-list?entity_id=undefined&promotion_id=1&traditional=undefined";
    $context = stream_context_create(['http' => ['timeout' => 30, 'ignore_errors' => true]]);
    $response = @file_get_contents($url, false, $context);

    if ($response === false) {
        echo json_encode(['status' => 'error', 'message' => 'Erreur de connexion à l\'API UCB']);
        return;
    }

    $data = json_decode($response, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        echo json_encode(['status' => 'error', 'message' => 'Réponse invalide de l\'API UCB']);
        return;
    }

    echo json_encode(['status' => 'success', 'data' => $data]);
}
?>
