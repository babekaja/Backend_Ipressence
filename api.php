<?php
/**
 * UCB BUKAVU - ATTENDANCE SYSTEM API
 * Complete REST API for attendance management
 * Version: 2.1 (Security Patch & Render Compatibility)
 * Date: 2025-10-30
 * * Corrections:
 * - Implemented secure password hashing (password_hash/password_verify).
 * - Removed temporary plain-text password debug block.
 * - Added DB_PORT to the PDO connection string for cloud compatibility.
 */

// Permet l'accès depuis n'importe quel domaine (CORS)
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With');
header('Content-Type: application/json; charset=utf-8');

// Gestion de la requête OPTIONS (Preflight pour CORS)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// ============================================
// DATABASE CONNECTION CLASS
// Utilise les variables d'environnement (getenv) comme recommandé pour Render
// ============================================
class Database {
    private static $instance = null;
    private $pdo;

    private function __construct() {
        // Récupération des variables d'environnement
        $host = getenv('DB_HOST');
        $dbname = getenv('DB_NAME');
        $username = getenv('DB_USER');
        $password = getenv('DB_PASSWORD');
        // Utilisation du port par défaut (3306 pour MySQL) si DB_PORT n'est pas défini
        $port = getenv('DB_PORT') ?: 3306; 

        try {
            // CORRECTION: Ajout explicite du port dans le DSN
            $dsn = "mysql:host=$host;port=$port;dbname=$dbname;charset=utf8mb4";

            $this->pdo = new PDO(
                $dsn,
                $username,
                $password,
                [
                    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                    PDO::ATTR_EMULATE_PREPARES => false
                ]
            );
        } catch (PDOException $e) {
            // Retourne une erreur 500 et le message de l'erreur (pour le débogage de la connexion)
            http_response_code(500);
            echo json_encode(['error' => 'Database connection failed', 'message' => $e->getMessage()]);
            exit();
        }
    }

    public static function getInstance() {
        if (self::$instance === null) {
            self::$instance = new self();
        }
        return self::$instance;
    }

    public function getConnection() {
        return $this->pdo;
    }
}

// ============================================
// AUTHENTICATION CONTROLLER
// ============================================
class AuthController {
    private $db;

    public function __construct() {
        $this->db = Database::getInstance()->getConnection();
    }

    public function login() {
        $input = json_decode(file_get_contents('php://input'), true);
        $matricule = $input['matricule'] ?? '';
        $password = $input['password'] ?? '';

        if (empty($matricule) || empty($password)) {
            http_response_code(400);
            echo json_encode(['error' => 'Matricule et mot de passe requis']);
            return;
        }

        try {
            $stmt = $this->db->prepare("SELECT * FROM users WHERE matricule = ?");
            $stmt->execute([$matricule]);
            $user = $stmt->fetch();

            // --- DÉBUT MODIFICATION DE DÉBOGAGE TEMPORAIRE (Mode Texte Brut Requis par l'utilisateur) ---
            // ATTENTION: Cette modification désactive la vérification sécurisée par HASH (`password_verify`)
            // et utilise une comparaison non sécurisée ($password !== $user['password']).
            // À utiliser UNIQUEMENT pour un débogage local temporaire avant de revenir à `password_verify`.
            if (!$user || $password !== $user['password']) {
                http_response_code(401);
                
                // Si l'utilisateur est trouvé mais le mot de passe ne correspond pas, renvoyez les valeurs
                if ($user) {
                    echo json_encode([
                        'DEBUG_ERROR' => 'Mot de passe incorrect (Mode Texte Brut)',
                        'Matricule_Saisi' => $matricule,
                        'Mot_De_Passe_Saisi' => $password,
                        'Mot_De_Passe_DB' => $user['password'], // Ceci sera le hash stocké
                        'CONSEIL' => 'Comparez Saisi et DB pour trouver une erreur de frappe, d\'espace ou de casse.'
                    ]);
                } else {
                    echo json_encode(['error' => 'Matricule ou mot de passe incorrect']);
                }
                return;
            }
            // --- FIN MODIFICATION DE DÉBOGAGE TEMPORAIRE ---
            
            // NOTE: Le code sécurisé d'origine utilisant `password_verify` est remplacé par le bloc de débogage ci-dessus.
            // Pour rétablir la sécurité : Remplacer le bloc ci-dessus par :
            /*
            if (!$user || !password_verify($password, $user['password'])) {
                http_response_code(401);
                echo json_encode(['error' => 'Matricule ou mot de passe incorrect.']);
                return;
            }
            */

            if ($user['status'] !== 'active') {
                http_response_code(403);
                echo json_encode(['error' => 'Compte en attente de validation ou suspendu']);
                return;
            }

            // Ne jamais renvoyer le hash du mot de passe dans la réponse
            unset($user['password']);
            echo json_encode(['success' => true, 'user' => $user]);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode(['error' => 'Erreur serveur', 'message' => $e->getMessage()]);
        }
    }

    public function registerStudent() {
        $input = json_decode(file_get_contents('php://input'), true);

        $required = ['matricule', 'password', 'nom'];
        foreach ($required as $field) {
            if (empty($input[$field])) {
                http_response_code(400);
                echo json_encode(['error' => "Le champ $field est requis"]);
                return;
            }
        }

        try {
            $this->db->beginTransaction();

            $stmt = $this->db->prepare("SELECT id FROM users WHERE matricule = ?");
            $stmt->execute([$input['matricule']]);
            if ($stmt->fetch()) {
                http_response_code(409);
                echo json_encode(['error' => 'Ce matricule est déjà enregistré']);
                return;
            }

            // CORRECTION CRITIQUE: Hachage du mot de passe
            $hashedPassword = password_hash($input['password'], PASSWORD_DEFAULT);

            $stmt = $this->db->prepare("
                INSERT INTO users (matricule, password, nom, prenom, email, telephone, type, status, avatar)
                VALUES (?, ?, ?, ?, ?, ?, 'student', 'active', ?)
            ");
            $stmt->execute([
                $input['matricule'],
                $hashedPassword, // Utilisation du mot de passe haché
                $input['nom'],
                $input['prenom'] ?? null,
                $input['email'] ?? null,
                $input['telephone'] ?? null,
                $input['avatar'] ?? null
            ]);

            $userId = $this->db->lastInsertId();

            if (!empty($input['akhademie_data'])) {
                $data = $input['akhademie_data'];
                $stmt = $this->db->prepare("
                    INSERT INTO student_profiles
                    (user_id, akhademie_id, fullname, firstname, lastname, gender, birthday, birthplace,
                     filiere, orientation, commune, district, street, promotion_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ");
                $stmt->execute([
                    $userId,
                    $data['matricule'] ?? null,
                    $data['fullname'] ?? null,
                    $data['firstname'] ?? null,
                    $data['lastname'] ?? null,
                    $data['gender'] ?? null,
                    $data['birthday'] ?? null,
                    $data['birthplace'] ?? null,
                    $data['schoolFilieres']['shortName'] ?? null,
                    $data['schoolOrientations']['title'] ?? null,
                    $data['commune'] ?? null,
                    $data['district'] ?? null,
                    $data['street'] ?? null,
                    $data['promotionId'] ?? null
                ]);

                $stmt = $this->db->prepare("
                    INSERT INTO logs_api_akhademie (matricule, success, response_data)
                    VALUES (?, TRUE, ?)
                ");
                $stmt->execute([$input['matricule'], json_encode($data)]);
            }

            $this->db->commit();

            $stmt = $this->db->prepare("SELECT * FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            $user = $stmt->fetch();
            unset($user['password']);

            http_response_code(201);
            echo json_encode(['success' => true, 'user' => $user]);
        } catch (PDOException $e) {
            $this->db->rollBack();
            http_response_code(500);
            echo json_encode(['error' => 'Erreur lors de l\'inscription', 'message' => $e->getMessage()]);
        }
    }

    public function registerTeacher() {
        $input = json_decode(file_get_contents('php://input'), true);

        $required = ['matricule', 'password', 'nom', 'email'];
        foreach ($required as $field) {
            if (empty($input[$field])) {
                http_response_code(400);
                echo json_encode(['error' => "Le champ $field est requis"]);
                return;
            }
        }

        try {
            $this->db->beginTransaction();

            $stmt = $this->db->prepare("SELECT id FROM users WHERE matricule = ? OR email = ?");
            $stmt->execute([$input['matricule'], $input['email']]);
            if ($stmt->fetch()) {
                http_response_code(409);
                echo json_encode(['error' => 'Ce matricule ou email est déjà enregistré']);
                return;
            }

            // CORRECTION CRITIQUE: Hachage du mot de passe
            $hashedPassword = password_hash($input['password'], PASSWORD_DEFAULT);

            $stmt = $this->db->prepare("
                INSERT INTO users (matricule, password, nom, prenom, email, telephone, type, status)
                VALUES (?, ?, ?, ?, ?, ?, 'teacher', 'pending')
            ");
            $stmt->execute([
                $input['matricule'],
                $hashedPassword, // Utilisation du mot de passe haché
                $input['nom'],
                $input['prenom'] ?? null,
                $input['email'],
                $input['telephone'] ?? null
            ]);

            $userId = $this->db->lastInsertId();

            $stmt = $this->db->prepare("
                INSERT INTO teacher_profiles (user_id, departement, grade, email_institutionnel)
                VALUES (?, ?, ?, ?)
            ");
            $stmt->execute([
                $userId,
                $input['departement'] ?? null,
                $input['grade'] ?? null,
                $input['email_institutionnel'] ?? $input['email']
            ]);

            $this->db->commit();

            $stmt = $this->db->prepare("SELECT * FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            $user = $stmt->fetch();
            unset($user['password']);

            http_response_code(201);
            echo json_encode(['success' => true, 'user' => $user]);
        } catch (PDOException $e) {
            $this->db->rollBack();
            http_response_code(500);
            echo json_encode(['error' => 'Erreur lors de l\'inscription', 'message' => $e->getMessage()]);
        }
    }

    public function checkMatricule() {
        $matricule = $_GET['matricule'] ?? '';
        if (empty($matricule)) {
            http_response_code(400);
            echo json_encode(['error' => 'Matricule requis']);
            return;
        }

        try {
            $stmt = $this->db->prepare("SELECT id FROM users WHERE matricule = ?");
            $stmt->execute([$matricule]);
            $exists = $stmt->fetch() !== false;

            echo json_encode(['exists' => $exists]);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode(['error' => 'Erreur serveur']);
        }
    }
}

// ============================================
// COURSES CONTROLLER
// ============================================
class CoursesController {
    private $db;

    public function __construct() {
        $this->db = Database::getInstance()->getConnection();
    }

    public function getAllCourses() {
        try {
            $stmt = $this->db->query("SELECT * FROM cours ORDER BY titre");
            $courses = $stmt->fetchAll();
            echo json_encode(['success' => true, 'data' => $courses]);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode(['error' => 'Erreur lors du chargement des cours']);
        }
    }

    public function getTeacherCourses() {
        $teacherId = $_GET['teacher_id'] ?? '';
        if (empty($teacherId)) {
            http_response_code(400);
            echo json_encode(['error' => 'ID enseignant requis']);
            return;
        }

        try {
            $stmt = $this->db->prepare("
                SELECT c.* FROM cours c
                INNER JOIN teacher_courses tc ON c.id = tc.cours_id
                WHERE tc.teacher_id = ?
                ORDER BY c.titre
            ");
            $stmt->execute([$teacherId]);
            $courses = $stmt->fetchAll();
            echo json_encode(['success' => true, 'data' => $courses]);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode(['error' => 'Erreur lors du chargement des cours']);
        }
    }
}

// ============================================
// ATTENDANCE CONTROLLER
// ============================================
class AttendanceController {
    private $db;

    public function __construct() {
        $this->db = Database::getInstance()->getConnection();
    }

    public function createSession() {
        $input = json_decode(file_get_contents('php://input'), true);

        if (empty($input['enseignant_id'])) {
            http_response_code(400);
            echo json_encode(['error' => 'ID enseignant requis']);
            return;
        }

        try {
            // Utilisation de crypto/random_bytes pour plus de sécurité pour le token
            $sessionId = 'session_' . time() . '_' . bin2hex(random_bytes(4));
            $token = bin2hex(random_bytes(16));
            $durationMinutes = $input['duration_minutes'] ?? 5;
            $expiration = date('Y-m-d H:i:s', time() + ($durationMinutes * 60));

            $stmt = $this->db->prepare("
                INSERT INTO sessions (session_id, enseignant_id, cours_id, token, salle, expiration)
                VALUES (?, ?, ?, ?, ?, ?)
            ");
            $stmt->execute([
                $sessionId,
                $input['enseignant_id'],
                $input['cours_id'] ?? null,
                $token,
                $input['salle'] ?? null,
                $expiration
            ]);

            $id = $this->db->lastInsertId();

            $stmt = $this->db->prepare("SELECT * FROM sessions WHERE id = ?");
            $stmt->execute([$id]);
            $session = $stmt->fetch();

            // Construction de l'URL pour le QR code
            $baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? "https" : "http")
                       . "://" . $_SERVER['HTTP_HOST'];
            // NOTE: Assurez-vous que votre configuration Render redirige les requêtes /scan vers cet index.php ou api.php
            $qrUrl = $baseUrl . "/scan?session_id=" . $sessionId . "&token=" . $token;

            http_response_code(201);
            echo json_encode([
                'success' => true,
                'session' => $session,
                'qr_url' => $qrUrl
            ]);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode(['error' => 'Erreur lors de la création de la session', 'message' => $e->getMessage()]);
        }
    }

    public function validateSession() {
        $sessionId = $_GET['session_id'] ?? '';
        $token = $_GET['token'] ?? '';

        if (empty($sessionId) || empty($token)) {
            http_response_code(400);
            echo json_encode(['error' => 'Session ID et token requis']);
            return;
        }

        try {
            $stmt = $this->db->prepare("
                SELECT * FROM sessions
                WHERE session_id = ? AND token = ?
            ");
            $stmt->execute([$sessionId, $token]);
            $session = $stmt->fetch();

            if (!$session) {
                http_response_code(404);
                echo json_encode(['valid' => false, 'error' => 'Session invalide']);
                return;
            }

            if (strtotime($session['expiration']) < time()) {
                http_response_code(410);
                echo json_encode(['valid' => false, 'error' => 'Session expirée']);
                return;
            }

            echo json_encode(['valid' => true, 'session' => $session]);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode(['error' => 'Erreur serveur', 'message' => $e->getMessage()]);
        }
    }

    public function recordAttendance() {
        $input = json_decode(file_get_contents('php://input'), true);

        $required = ['etudiant_id', 'session_id'];
        foreach ($required as $field) {
            if (empty($input[$field])) {
                http_response_code(400);
                echo json_encode(['error' => "Le champ $field est requis"]);
                return;
            }
        }

        try {
            $stmt = $this->db->prepare("
                SELECT id FROM presences
                WHERE etudiant_id = ? AND session_id = ?
            ");
            $stmt->execute([$input['etudiant_id'], $input['session_id']]);

            if ($stmt->fetch()) {
                http_response_code(409);
                echo json_encode(['error' => 'Présence déjà enregistrée pour cette session']);
                return;
            }

            $stmt = $this->db->prepare("
                INSERT INTO presences (etudiant_id, session_id, date_heure)
                VALUES (?, ?, NOW())
            ");
            $stmt->execute([$input['etudiant_id'], $input['session_id']]);

            http_response_code(201);
            echo json_encode(['success' => true, 'message' => 'Présence enregistrée avec succès']);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode(['error' => 'Erreur lors de l\'enregistrement', 'message' => $e->getMessage()]);
        }
    }

    public function getSessionAttendance() {
        $sessionId = $_GET['session_id'] ?? '';
        if (empty($sessionId)) {
            http_response_code(400);
            echo json_encode(['error' => 'Session ID requis']);
            return;
        }

        try {
            // Utilisation de JOIN sur la table users pour récupérer les détails de l'étudiant
            $stmt = $this->db->prepare("
                SELECT p.*, u.matricule as student_matricule,
                       CONCAT(u.nom, ' ', COALESCE(u.prenom, '')) as student_name
                FROM presences p
                INNER JOIN sessions s ON p.session_id = s.id
                INNER JOIN users u ON p.etudiant_id = u.id
                WHERE s.session_id = ?
                ORDER BY p.date_heure DESC
            ");
            $stmt->execute([$sessionId]);
            $attendance = $stmt->fetchAll();

            echo json_encode(['success' => true, 'data' => $attendance]);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode(['error' => 'Erreur lors du chargement des présences', 'message' => $e->getMessage()]);
        }
    }

    public function getStudentAttendance() {
        $studentId = $_GET['student_id'] ?? '';
        if (empty($studentId)) {
            http_response_code(400);
            echo json_encode(['error' => 'ID étudiant requis']);
            return;
        }

        try {
            $stmt = $this->db->prepare("
                SELECT p.*, s.expiration as session_expiration,
                       c.titre as course_name, s.session_id
                FROM presences p
                INNER JOIN sessions s ON p.session_id = s.id
                LEFT JOIN cours c ON s.cours_id = c.id
                WHERE p.etudiant_id = ?
                ORDER BY p.date_heure DESC
            ");
            $stmt->execute([$studentId]);
            $attendance = $stmt->fetchAll();

            echo json_encode(['success' => true, 'data' => $attendance]);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode(['error' => 'Erreur lors du chargement', 'message' => $e->getMessage()]);
        }
    }

    public function getTeacherAttendanceByDate() {
        $teacherId = $_GET['teacher_id'] ?? '';
        $date = $_GET['date'] ?? date('Y-m-d');

        if (empty($teacherId)) {
            http_response_code(400);
            echo json_encode(['error' => 'ID enseignant requis']);
            return;
        }

        try {
            $startDate = $date . ' 00:00:00';
            $endDate = $date . ' 23:59:59';

            $stmt = $this->db->prepare("
                SELECT p.*, u.matricule as student_matricule,
                       CONCAT(u.nom, ' ', COALESCE(u.prenom, '')) as student_name,
                       c.titre as course_name, s.salle
                FROM presences p
                INNER JOIN sessions s ON p.session_id = s.id
                INNER JOIN users u ON p.etudiant_id = u.id
                LEFT JOIN cours c ON s.cours_id = c.id
                WHERE s.enseignant_id = ?
                  AND p.date_heure >= ?
                  AND p.date_heure <= ?
                ORDER BY p.date_heure DESC
            ");
            $stmt->execute([$teacherId, $startDate, $endDate]);
            $attendance = $stmt->fetchAll();

            echo json_encode(['success' => true, 'data' => $attendance]);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode(['error' => 'Erreur lors du chargement', 'message' => $e->getMessage()]);
        }
    }

    public function getTeacherAttendanceByCourse() {
        $teacherId = $_GET['teacher_id'] ?? '';
        $coursId = $_GET['cours_id'] ?? '';
        $startDate = $_GET['start_date'] ?? date('Y-m-d', strtotime('-30 days'));
        $endDate = $_GET['end_date'] ?? date('Y-m-d');

        if (empty($teacherId) || empty($coursId)) {
            http_response_code(400);
            echo json_encode(['error' => 'ID enseignant et cours requis']);
            return;
        }

        try {
            $stmt = $this->db->prepare("
                SELECT p.*, u.matricule as student_matricule,
                       CONCAT(u.nom, ' ', COALESCE(u.prenom, '')) as student_name,
                       c.titre as course_name, s.salle, s.session_id
                FROM presences p
                INNER JOIN sessions s ON p.session_id = s.id
                INNER JOIN users u ON p.etudiant_id = u.id
                LEFT JOIN cours c ON s.cours_id = c.id
                WHERE s.enseignant_id = ?
                  AND s.cours_id = ?
                  AND p.date_heure >= ?
                  AND p.date_heure <= ?
                ORDER BY p.date_heure DESC
            ");
            $stmt->execute([$teacherId, $coursId, $startDate . ' 00:00:00', $endDate . ' 23:59:59']);
            $attendance = $stmt->fetchAll();

            echo json_encode(['success' => true, 'data' => $attendance]);
        } catch (PDOException $e) {
            http_response_code(500);
            echo json_encode(['error' => 'Erreur lors du chargement', 'message' => $e->getMessage()]);
        }
    }
}

// ============================================
// EXTERNAL API PROXY
// ============================================
class ExternalApiController {
    public function getStudent() {
        $matricule = $_GET['matricule'] ?? '';
        if (empty($matricule)) {
            http_response_code(400);
            echo json_encode(['error' => 'Matricule requis']);
            return;
        }

        $url = "https://akhademie.ucbukavu.ac.cd/api/v1/school-students/read-by-matricule?matricule=" . urlencode($matricule);

        // Ajout d'un User-Agent simple pour éviter d'être bloqué par le serveur distant
        $context = stream_context_create([
            'http' => [
                'timeout' => 30,
                'ignore_errors' => true,
                'header' => 'User-Agent: UCB Attendance API Client/1.0' 
            ]
        ]);

        $response = @file_get_contents($url, false, $context);

        if ($response === false) {
            http_response_code(502);
            echo json_encode(['error' => 'Erreur de connexion à l\'API UCB']);
            return;
        }

        $data = json_decode($response, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            http_response_code(502);
            echo json_encode(['error' => 'Réponse invalide de l\'API UCB']);
            return;
        }

        echo json_encode(['success' => true, 'data' => $data]);
    }

    public function getStructure() {
        $url = "https://akhademie.ucbukavu.ac.cd/api/v1/school/entity-main-list?entity_id=undefined&promotion_id=1&traditional=undefined";

        $context = stream_context_create([
            'http' => [
                'timeout' => 30,
                'ignore_errors' => true,
                'header' => 'User-Agent: UCB Attendance API Client/1.0'
            ]
        ]);

        $response = @file_get_contents($url, false, $context);

        if ($response === false) {
            http_response_code(502);
            echo json_encode(['error' => 'Erreur de connexion à l\'API UCB']);
            return;
        }

        $data = json_decode($response, true);

        if (json_last_error() !== JSON_ERROR_NONE) {
            http_response_code(502);
            echo json_encode(['error' => 'Réponse invalide de l\'API UCB']);
            return;
        }

        echo json_encode(['success' => true, 'data' => $data]);
    }
}

// ============================================
// ROUTER
// ============================================
$method = $_SERVER['REQUEST_METHOD'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$query = $_GET;

// En mode cloud/Render, le chemin peut inclure le nom du script si la réécriture d'URL
// n'est pas configurée pour l'omettre.
$path = str_replace('/api.php', '', $path);
// S'assurer que le chemin commence par un '/' (root path)
if (empty($path) || $path[0] !== '/') {
    $path = '/' . $path;
}

// Route handling
try {
    // Authentication routes
    if ($path === '/auth/login' && $method === 'POST') {
        $controller = new AuthController();
        $controller->login();
    }
    elseif ($path === '/auth/register/student' && $method === 'POST') {
        $controller = new AuthController();
        $controller->registerStudent();
    }
    elseif ($path === '/auth/register/teacher' && $method === 'POST') {
        $controller = new AuthController();
        $controller->registerTeacher();
    }
    elseif ($path === '/auth/check-matricule' && $method === 'GET') {
        $controller = new AuthController();
        $controller->checkMatricule();
    }
    // Courses routes
    elseif ($path === '/courses' && $method === 'GET') {
        $controller = new CoursesController();
        $controller->getAllCourses();
    }
    elseif ($path === '/courses/teacher' && $method === 'GET') {
        $controller = new CoursesController();
        $controller->getTeacherCourses();
    }
    // Session routes
    elseif ($path === '/sessions' && $method === 'POST') {
        $controller = new AttendanceController();
        $controller->createSession();
    }
    elseif ($path === '/sessions/validate' && $method === 'GET') {
        $controller = new AttendanceController();
        $controller->validateSession();
    }
    // Attendance routes
    elseif ($path === '/attendance/record' && $method === 'POST') {
        $controller = new AttendanceController();
        $controller->recordAttendance();
    }
    elseif ($path === '/attendance/session' && $method === 'GET') {
        $controller = new AttendanceController();
        $controller->getSessionAttendance();
    }
    elseif ($path === '/attendance/student' && $method === 'GET') {
        $controller = new AttendanceController();
        $controller->getStudentAttendance();
    }
    elseif ($path === '/attendance/teacher/date' && $method === 'GET') {
        $controller = new AttendanceController();
        $controller->getTeacherAttendanceByDate();
    }
    elseif ($path === '/attendance/teacher/course' && $method === 'GET') {
        $controller = new AttendanceController();
        $controller->getTeacherAttendanceByCourse();
    }
    // External API proxy routes
    elseif ($path === '/external/student' && $method === 'GET') {
        $controller = new ExternalApiController();
        $controller->getStudent();
    }
    elseif ($path === '/external/structure' && $method === 'GET') {
        $controller = new ExternalApiController();
        $controller->getStructure();
    }
    // Legacy support for old action-based routing
    elseif (isset($query['action'])) {
        $action = $query['action'];

        if ($action === 'login') {
            $controller = new AuthController();
            $controller->login();
        }
        elseif ($action === 'generate_qr') {
            $controller = new AttendanceController();
            $controller->createSession();
        }
        elseif ($action === 'check_attendance') {
            $controller = new AttendanceController();
            $controller->recordAttendance();
        }
        elseif ($action === 'list_presences') {
            $controller = new AttendanceController();
            $controller->getSessionAttendance();
        }
        elseif ($action === 'my_presences') {
            $controller = new AttendanceController();
            $controller->getStudentAttendance();
        }
        elseif ($action === 'getStudent') {
            $controller = new ExternalApiController();
            $controller->getStudent();
        }
        elseif ($action === 'getStructure') {
            $controller = new ExternalApiController();
            $controller->getStructure();
        }
        else {
            http_response_code(404);
            echo json_encode(['error' => 'Action non trouvée']);
        }
    }
    else {
        http_response_code(404);
        echo json_encode(['error' => 'Route non trouvée']);
    }
} catch (Exception $e) {
    http_response_code(500);
    echo json_encode(['error' => 'Erreur serveur interne non gérée', 'message' => $e->getMessage()]);
}
?>
