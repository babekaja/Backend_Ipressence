<?php
/**
 * UCB BUKAVU - ATTENDANCE SYSTEM API
 * Version: corrected for Render (2025-10-30)
 */

declare(strict_types=1);

// ---------------------------
// CORS & Headers
// ---------------------------
header('Access-Control-Allow-Origin: *');
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-Requested-With, Accept, Origin');
header('Content-Type: application/json; charset=utf-8');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// ---------------------------
// Helpers
// ---------------------------
function jsonResponse($data, int $status = 200): void {
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit();
}

function getJsonInput(): array {
    $raw = file_get_contents('php://input') ?: '';
    if ($raw === '') return [];
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function curlGet(string $url, int $timeout = 30): ?string {
    if (!function_exists('curl_init')) {
        // try file_get_contents as last resort
        $context = stream_context_create(['http' => ['timeout' => $timeout, 'ignore_errors' => true]]);
        return @file_get_contents($url, false, $context) ?: null;
    }
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, $timeout);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    $res = curl_exec($ch);
    $err = curl_error($ch);
    curl_close($ch);
    return $err ? null : $res;
}

function getBaseUrl(): string {
    $https = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off');
    $scheme = $https ? 'https' : 'http';
    $host = $_SERVER['HTTP_HOST'] ?? 'localhost';
    return "{$scheme}://{$host}";
}

// ---------------------------
// DATABASE
// ---------------------------
class Database {
    private static ?Database $instance = null;
    private PDO $pdo;

    private function __construct() {
        $host = getenv('DB_HOST') ?: '127.0.0.1';
        $dbname = getenv('DB_NAME') ?: 'ucb';
        $username = getenv('DB_USER') ?: 'root';
        $password = getenv('DB_PASSWORD') ?: '';
        $port = getenv('DB_PORT') ?: 3306;

        $dsn = "mysql:host={$host};port={$port};dbname={$dbname};charset=utf8mb4";
        try {
            $this->pdo = new PDO($dsn, $username, $password, [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES => false,
            ]);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'Database connection failed', 'message' => $e->getMessage()], 500);
        }
    }

    public static function getInstance(): Database {
        if (self::$instance === null) {
            self::$instance = new Database();
        }
        return self::$instance;
    }

    public function getConnection(): PDO {
        return $this->pdo;
    }
}

// ---------------------------
// AUTH CONTROLLER
// ---------------------------
class AuthController {
    private PDO $db;

    public function __construct() {
        $this->db = Database::getInstance()->getConnection();
    }

    public function login(): void {
        $input = getJsonInput();
        $matricule = trim((string)($input['matricule'] ?? ''));
        $password = (string)($input['password'] ?? '');

        if ($matricule === '' || $password === '') {
            jsonResponse(['error' => 'Matricule et mot de passe requis'], 400);
        }

        try {
            $stmt = $this->db->prepare("SELECT * FROM users WHERE matricule = :m LIMIT 1");
            $stmt->execute([':m' => $matricule]);
            $user = $stmt->fetch();

            if (!$user) {
                jsonResponse(['error' => 'Matricule ou mot de passe incorrect'], 401);
            }

            // password_verify (expects hashed password stored)
            $dbPass = $user['password'] ?? '';
            if (!password_verify($password, $dbPass)) {
                jsonResponse(['error' => 'Matricule ou mot de passe incorrect'], 401);
            }

            if (($user['status'] ?? 'inactive') !== 'active') {
                jsonResponse(['error' => 'Compte en attente de validation ou suspendu'], 403);
            }

            unset($user['password']);
            jsonResponse(['success' => true, 'user' => $user], 200);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'Erreur serveur', 'message' => $e->getMessage()], 500);
        }
    }

    public function registerStudent(): void {
        $input = getJsonInput();
        $required = ['matricule', 'password', 'nom'];

        foreach ($required as $f) {
            if (empty($input[$f])) jsonResponse(['error' => "Le champ $f est requis"], 400);
        }

        $matricule = trim($input['matricule']);
        $password = $input['password'];
        $nom = trim($input['nom']);

        try {
            $this->db->beginTransaction();

            $stmt = $this->db->prepare("SELECT id FROM users WHERE matricule = :m LIMIT 1");
            $stmt->execute([':m' => $matricule]);
            if ($stmt->fetch()) {
                $this->db->rollBack();
                jsonResponse(['error' => 'Ce matricule est déjà enregistré'], 409);
            }

            // Hash password
            $hashed = password_hash($password, PASSWORD_DEFAULT);

            $stmt = $this->db->prepare("
                INSERT INTO users (matricule, password, nom, prenom, email, telephone, type, status, avatar)
                VALUES (:mat, :pass, :nom, :prenom, :email, :tel, 'student', 'active', :avatar)
            ");
            $stmt->execute([
                ':mat' => $matricule,
                ':pass' => $hashed,
                ':nom' => $nom,
                ':prenom' => $input['prenom'] ?? null,
                ':email' => $input['email'] ?? null,
                ':tel' => $input['telephone'] ?? null,
                ':avatar' => $input['avatar'] ?? null,
            ]);

            $userId = (int)$this->db->lastInsertId();

            if (!empty($input['akhademie_data']) && is_array($input['akhademie_data'])) {
                $data = $input['akhademie_data'];
                $stmt = $this->db->prepare("
                    INSERT INTO student_profiles
                    (user_id, akhademie_id, fullname, firstname, lastname, gender, birthday, birthplace,
                     filiere, orientation, commune, district, street, promotion_id)
                    VALUES (:uid, :akh_id, :fullname, :firstname, :lastname, :gender, :birthday, :birthplace,
                            :filiere, :orientation, :commune, :district, :street, :promotion)
                ");
                $stmt->execute([
                    ':uid' => $userId,
                    ':akh_id' => $data['matricule'] ?? null,
                    ':fullname' => $data['fullname'] ?? null,
                    ':firstname' => $data['firstname'] ?? null,
                    ':lastname' => $data['lastname'] ?? null,
                    ':gender' => $data['gender'] ?? null,
                    ':birthday' => $data['birthday'] ?? null,
                    ':birthplace' => $data['birthplace'] ?? null,
                    ':filiere' => $data['schoolFilieres']['shortName'] ?? null,
                    ':orientation' => $data['schoolOrientations']['title'] ?? null,
                    ':commune' => $data['commune'] ?? null,
                    ':district' => $data['district'] ?? null,
                    ':street' => $data['street'] ?? null,
                    ':promotion' => $data['promotionId'] ?? null,
                ]);

                $stmt = $this->db->prepare("INSERT INTO logs_api_akhademie (matricule, success, response_data) VALUES (:mat, 1, :resp)");
                $stmt->execute([':mat' => $matricule, ':resp' => json_encode($data)]);
            }

            $this->db->commit();

            $stmt = $this->db->prepare("SELECT id, matricule, nom, prenom, email, telephone, type, status, avatar FROM users WHERE id = :id LIMIT 1");
            $stmt->execute([':id' => $userId]);
            $user = $stmt->fetch();

            jsonResponse(['success' => true, 'user' => $user], 201);
        } catch (PDOException $e) {
            $this->db->rollBack();
            jsonResponse(['error' => "Erreur lors de l'inscription", 'message' => $e->getMessage()], 500);
        }
    }

    public function registerTeacher(): void {
        $input = getJsonInput();
        $required = ['matricule', 'password', 'nom', 'email'];
        foreach ($required as $f) {
            if (empty($input[$f])) jsonResponse(['error' => "Le champ $f est requis"], 400);
        }

        $matricule = trim($input['matricule']);
        $password = $input['password'];
        $nom = trim($input['nom']);
        $email = trim($input['email']);

        try {
            $this->db->beginTransaction();

            $stmt = $this->db->prepare("SELECT id FROM users WHERE matricule = :m OR email = :e LIMIT 1");
            $stmt->execute([':m' => $matricule, ':e' => $email]);
            if ($stmt->fetch()) {
                $this->db->rollBack();
                jsonResponse(['error' => 'Ce matricule ou email est déjà enregistré'], 409);
            }

            $hashed = password_hash($password, PASSWORD_DEFAULT);

            $stmt = $this->db->prepare("
                INSERT INTO users (matricule, password, nom, prenom, email, telephone, type, status)
                VALUES (:mat, :pass, :nom, :prenom, :email, :tel, 'teacher', 'pending')
            ");
            $stmt->execute([
                ':mat' => $matricule,
                ':pass' => $hashed,
                ':nom' => $nom,
                ':prenom' => $input['prenom'] ?? null,
                ':email' => $email,
                ':tel' => $input['telephone'] ?? null,
            ]);

            $userId = (int)$this->db->lastInsertId();

            $stmt = $this->db->prepare("INSERT INTO teacher_profiles (user_id, departement, grade, email_institutionnel) VALUES (:uid, :dept, :grade, :inst)");
            $stmt->execute([
                ':uid' => $userId,
                ':dept' => $input['departement'] ?? null,
                ':grade' => $input['grade'] ?? null,
                ':inst' => $input['email_institutionnel'] ?? $email,
            ]);

            $this->db->commit();

            $stmt = $this->db->prepare("SELECT id, matricule, nom, prenom, email, telephone, type, status FROM users WHERE id = :id LIMIT 1");
            $stmt->execute([':id' => $userId]);
            $user = $stmt->fetch();

            jsonResponse(['success' => true, 'user' => $user], 201);
        } catch (PDOException $e) {
            $this->db->rollBack();
            jsonResponse(['error' => "Erreur lors de l'inscription", 'message' => $e->getMessage()], 500);
        }
    }

    public function checkMatricule(): void {
        $matricule = trim((string)($_GET['matricule'] ?? ''));
        if ($matricule === '') jsonResponse(['error' => 'Matricule requis'], 400);

        try {
            $stmt = $this->db->prepare("SELECT id FROM users WHERE matricule = :m LIMIT 1");
            $stmt->execute([':m' => $matricule]);
            $exists = (bool)$stmt->fetch();
            jsonResponse(['exists' => $exists]);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'Erreur serveur', 'message' => $e->getMessage()], 500);
        }
    }
}

// ---------------------------
// COURSES CONTROLLER
// ---------------------------
class CoursesController {
    private PDO $db;
    public function __construct() { $this->db = Database::getInstance()->getConnection(); }

    public function getAllCourses(): void {
        try {
            $stmt = $this->db->query("SELECT * FROM cours ORDER BY titre");
            $courses = $stmt->fetchAll();
            jsonResponse(['success' => true, 'data' => $courses]);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'Erreur lors du chargement des cours', 'message' => $e->getMessage()], 500);
        }
    }

    public function getTeacherCourses(): void {
        $teacherId = $_GET['teacher_id'] ?? '';
        if ($teacherId === '') jsonResponse(['error' => 'ID enseignant requis'], 400);
        try {
            $stmt = $this->db->prepare("
                SELECT c.* FROM cours c
                INNER JOIN teacher_courses tc ON c.id = tc.cours_id
                WHERE tc.teacher_id = :tid
                ORDER BY c.titre
            ");
            $stmt->execute([':tid' => $teacherId]);
            $courses = $stmt->fetchAll();
            jsonResponse(['success' => true, 'data' => $courses]);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'Erreur lors du chargement des cours', 'message' => $e->getMessage()], 500);
        }
    }
}

// ---------------------------
// ATTENDANCE CONTROLLER
// ---------------------------
class AttendanceController {
    private PDO $db;
    public function __construct() { $this->db = Database::getInstance()->getConnection(); }

    public function createSession(): void {
        $input = getJsonInput();
        $enseignantId = $input['enseignant_id'] ?? null;
        if (empty($enseignantId)) jsonResponse(['error' => 'ID enseignant requis'], 400);

        try {
            $sessionId = 'session_' . time() . '_' . bin2hex(random_bytes(4));
            $token = bin2hex(random_bytes(16));
            $durationMinutes = (int)($input['duration_minutes'] ?? 5);
            $expiration = date('Y-m-d H:i:s', time() + max(1, $durationMinutes) * 60);

            $stmt = $this->db->prepare("
                INSERT INTO sessions (session_id, enseignant_id, cours_id, token, salle, expiration)
                VALUES (:sid, :enseignant, :cours, :token, :salle, :exp)
            ");
            $stmt->execute([
                ':sid' => $sessionId,
                ':enseignant' => $enseignantId,
                ':cours' => $input['cours_id'] ?? null,
                ':token' => $token,
                ':salle' => $input['salle'] ?? null,
                ':exp' => $expiration,
            ]);

            $dbId = (int)$this->db->lastInsertId();

            $stmt = $this->db->prepare("SELECT * FROM sessions WHERE id = :id LIMIT 1");
            $stmt->execute([':id' => $dbId]);
            $session = $stmt->fetch();

            $baseUrl = getBaseUrl();
            $qrUrl = "{$baseUrl}/scan?session_id={$sessionId}&token={$token}";

            jsonResponse(['success' => true, 'session' => $session, 'qr_url' => $qrUrl], 201);
        } catch (Exception $e) {
            jsonResponse(['error' => 'Erreur lors de la création de la session', 'message' => $e->getMessage()], 500);
        }
    }

    public function validateSession(): void {
        $sessionId = $_GET['session_id'] ?? '';
        $token = $_GET['token'] ?? '';
        if ($sessionId === '' || $token === '') jsonResponse(['error' => 'Session ID et token requis'], 400);

        try {
            $stmt = $this->db->prepare("SELECT * FROM sessions WHERE session_id = :sid AND token = :token LIMIT 1");
            $stmt->execute([':sid' => $sessionId, ':token' => $token]);
            $session = $stmt->fetch();

            if (!$session) jsonResponse(['valid' => false, 'error' => 'Session invalide'], 404);
            if (strtotime($session['expiration']) < time()) jsonResponse(['valid' => false, 'error' => 'Session expirée'], 410);

            jsonResponse(['valid' => true, 'session' => $session]);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'Erreur serveur', 'message' => $e->getMessage()], 500);
        }
    }

    public function recordAttendance(): void {
        $input = getJsonInput();
        // Accept either etudiant_id + session_db_id (numeric) OR etudiant_id + session_id (string)
        $studentId = $input['etudiant_id'] ?? null;
        $sessionDbId = isset($input['session_db_id']) ? (int)$input['session_db_id'] : null;
        $sessionSid = $input['session_id'] ?? null;

        if (empty($studentId) || (empty($sessionDbId) && empty($sessionSid))) {
            jsonResponse(['error' => 'etudiant_id et session_db_id ou session_id requis'], 400);
        }

        try {
            // Resolve session_db_id if only session_id (string) provided
            if (empty($sessionDbId) && !empty($sessionSid)) {
                $stmt = $this->db->prepare("SELECT id, expiration FROM sessions WHERE session_id = :sid LIMIT 1");
                $stmt->execute([':sid' => $sessionSid]);
                $s = $stmt->fetch();
                if (!$s) jsonResponse(['error' => 'Session introuvable'], 404);
                if (strtotime($s['expiration']) < time()) jsonResponse(['error' => 'Session expirée'], 410);
                $sessionDbId = (int)$s['id'];
            }

            // Check duplicate
            $stmt = $this->db->prepare("SELECT id FROM presences WHERE etudiant_id = :eid AND session_id = :sid LIMIT 1");
            $stmt->execute([':eid' => $studentId, ':sid' => $sessionDbId]);
            if ($stmt->fetch()) jsonResponse(['error' => 'Présence déjà enregistrée pour cette session'], 409);

            $stmt = $this->db->prepare("INSERT INTO presences (etudiant_id, session_id, date_heure) VALUES (:eid, :sid, NOW())");
            $stmt->execute([':eid' => $studentId, ':sid' => $sessionDbId]);

            jsonResponse(['success' => true, 'message' => 'Présence enregistrée avec succès'], 201);
        } catch (PDOException $e) {
            jsonResponse(['error' => "Erreur lors de l'enregistrement", 'message' => $e->getMessage()], 500);
        }
    }

    public function getSessionAttendance(): void {
        $sessionId = $_GET['session_id'] ?? '';
        if ($sessionId === '') jsonResponse(['error' => 'Session ID requis'], 400);

        try {
            // Accept either numeric DB id or session_id string
            if (ctype_digit($sessionId)) {
                $sql = "WHERE p.session_id = :sid";
                $param = [':sid' => (int)$sessionId];
            } else {
                // find db id by session_id string
                $stmt = $this->db->prepare("SELECT id FROM sessions WHERE session_id = :s LIMIT 1");
                $stmt->execute([':s' => $sessionId]);
                $row = $stmt->fetch();
                if (!$row) jsonResponse(['error' => 'Session introuvable'], 404);
                $sql = "WHERE p.session_id = :sid";
                $param = [':sid' => (int)$row['id']];
            }

            $stmt = $this->db->prepare("
                SELECT p.*, u.matricule as student_matricule,
                       CONCAT(u.nom, ' ', COALESCE(u.prenom, '')) as student_name
                FROM presences p
                INNER JOIN users u ON p.etudiant_id = u.id
                {$sql}
                ORDER BY p.date_heure DESC
            ");
            $stmt->execute($param);
            $attendance = $stmt->fetchAll();
            jsonResponse(['success' => true, 'data' => $attendance]);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'Erreur lors du chargement des présences', 'message' => $e->getMessage()], 500);
        }
    }

    public function getStudentAttendance(): void {
        $studentId = $_GET['student_id'] ?? '';
        if ($studentId === '') jsonResponse(['error' => 'ID étudiant requis'], 400);

        try {
            $stmt = $this->db->prepare("
                SELECT p.*, s.expiration as session_expiration,
                       c.titre as course_name, s.session_id
                FROM presences p
                INNER JOIN sessions s ON p.session_id = s.id
                LEFT JOIN cours c ON s.cours_id = c.id
                WHERE p.etudiant_id = :sid
                ORDER BY p.date_heure DESC
            ");
            $stmt->execute([':sid' => $studentId]);
            $attendance = $stmt->fetchAll();
            jsonResponse(['success' => true, 'data' => $attendance]);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'Erreur lors du chargement', 'message' => $e->getMessage()], 500);
        }
    }

    public function getTeacherAttendanceByDate(): void {
        $teacherId = $_GET['teacher_id'] ?? '';
        $date = $_GET['date'] ?? date('Y-m-d');

        if ($teacherId === '') jsonResponse(['error' => 'ID enseignant requis'], 400);

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
                WHERE s.enseignant_id = :tid
                  AND p.date_heure BETWEEN :start AND :end
                ORDER BY p.date_heure DESC
            ");
            $stmt->execute([':tid' => $teacherId, ':start' => $startDate, ':end' => $endDate]);
            $attendance = $stmt->fetchAll();
            jsonResponse(['success' => true, 'data' => $attendance]);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'Erreur lors du chargement', 'message' => $e->getMessage()], 500);
        }
    }

    public function getTeacherAttendanceByCourse(): void {
        $teacherId = $_GET['teacher_id'] ?? '';
        $coursId = $_GET['cours_id'] ?? '';
        $startDate = $_GET['start_date'] ?? date('Y-m-d', strtotime('-30 days'));
        $endDate = $_GET['end_date'] ?? date('Y-m-d');

        if ($teacherId === '' || $coursId === '') jsonResponse(['error' => 'ID enseignant et cours requis'], 400);

        try {
            $stmt = $this->db->prepare("
                SELECT p.*, u.matricule as student_matricule,
                       CONCAT(u.nom, ' ', COALESCE(u.prenom, '')) as student_name,
                       c.titre as course_name, s.salle, s.session_id
                FROM presences p
                INNER JOIN sessions s ON p.session_id = s.id
                INNER JOIN users u ON p.etudiant_id = u.id
                LEFT JOIN cours c ON s.cours_id = c.id
                WHERE s.enseignant_id = :tid
                  AND s.cours_id = :cid
                  AND p.date_heure BETWEEN :start AND :end
                ORDER BY p.date_heure DESC
            ");
            $stmt->execute([
                ':tid' => $teacherId,
                ':cid' => $coursId,
                ':start' => $startDate . ' 00:00:00',
                ':end' => $endDate . ' 23:59:59'
            ]);
            $attendance = $stmt->fetchAll();
            jsonResponse(['success' => true, 'data' => $attendance]);
        } catch (PDOException $e) {
            jsonResponse(['error' => 'Erreur lors du chargement', 'message' => $e->getMessage()], 500);
        }
    }
}

// ---------------------------
// EXTERNAL API PROXY
// ---------------------------
class ExternalApiController {
    public function getStudent(): void {
        $matricule = trim((string)($_GET['matricule'] ?? ''));
        if ($matricule === '') jsonResponse(['error' => 'Matricule requis'], 400);

        $url = "https://akhademie.ucbukavu.ac.cd/api/v1/school-students/read-by-matricule?matricule=" . urlencode($matricule);
        $response = curlGet($url, 30);
        if ($response === null) jsonResponse(['error' => "Erreur de connexion à l'API UCB"], 502);

        $data = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) jsonResponse(['error' => "Réponse invalide de l'API UCB"], 502);

        jsonResponse(['success' => true, 'data' => $data]);
    }

    public function getStructure(): void {
        $url = "https://akhademie.ucbukavu.ac.cd/api/v1/school/entity-main-list?entity_id=undefined&promotion_id=1&traditional=undefined";
        $response = curlGet($url, 30);
        if ($response === null) jsonResponse(['error' => "Erreur de connexion à l'API UCB"], 502);

        $data = json_decode($response, true);
        if (json_last_error() !== JSON_ERROR_NONE) jsonResponse(['error' => "Réponse invalide de l'API UCB"], 502);

        jsonResponse(['success' => true, 'data' => $data]);
    }
}

// ---------------------------
// Router
// ---------------------------
$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
$uri = parse_url($_SERVER['REQUEST_URI'] ?? '/', PHP_URL_PATH) ?: '/';

// remove SCRIPT_NAME part if present (works for render/deploy)
$scriptName = $_SERVER['SCRIPT_NAME'] ?? '';
if ($scriptName !== '' && str_starts_with($uri, dirname($scriptName))) {
    $uri = substr($uri, strlen(dirname($scriptName)));
    if ($uri === '') $uri = '/';
}

// normalize trailing slash
$path = rtrim($uri, '/');
if ($path === '') $path = '/';

try {
    // AUTH
    if ($path === '/auth/login' && $method === 'POST') {
        (new AuthController())->login();
    } elseif ($path === '/auth/register/student' && $method === 'POST') {
        (new AuthController())->registerStudent();
    } elseif ($path === '/auth/register/teacher' && $method === 'POST') {
        (new AuthController())->registerTeacher();
    } elseif ($path === '/auth/check-matricule' && $method === 'GET') {
        (new AuthController())->checkMatricule();
    }
    // COURSES
    elseif ($path === '/courses' && $method === 'GET') {
        (new CoursesController())->getAllCourses();
    } elseif ($path === '/courses/teacher' && $method === 'GET') {
        (new CoursesController())->getTeacherCourses();
    }
    // SESSIONS
    elseif ($path === '/sessions' && $method === 'POST') {
        (new AttendanceController())->createSession();
    } elseif ($path === '/sessions/validate' && $method === 'GET') {
        (new AttendanceController())->validateSession();
    }
    // ATTENDANCE
    elseif ($path === '/attendance/record' && $method === 'POST') {
        (new AttendanceController())->recordAttendance();
    } elseif ($path === '/attendance/session' && $method === 'GET') {
        (new AttendanceController())->getSessionAttendance();
    } elseif ($path === '/attendance/student' && $method === 'GET') {
        (new AttendanceController())->getStudentAttendance();
    } elseif ($path === '/attendance/teacher/date' && $method === 'GET') {
        (new AttendanceController())->getTeacherAttendanceByDate();
    } elseif ($path === '/attendance/teacher/course' && $method === 'GET') {
        (new AttendanceController())->getTeacherAttendanceByCourse();
    }
    // EXTERNAL
    elseif ($path === '/external/student' && $method === 'GET') {
        (new ExternalApiController())->getStudent();
    } elseif ($path === '/external/structure' && $method === 'GET') {
        (new ExternalApiController())->getStructure();
    }
    // Legacy query action support
    elseif (isset($_GET['action'])) {
        $action = $_GET['action'];
        switch ($action) {
            case 'login': (new AuthController())->login(); break;
            case 'generate_qr': (new AttendanceController())->createSession(); break;
            case 'check_attendance': (new AttendanceController())->recordAttendance(); break;
            case 'list_presences': (new AttendanceController())->getSessionAttendance(); break;
            case 'my_presences': (new AttendanceController())->getStudentAttendance(); break;
            case 'getStudent': (new ExternalApiController())->getStudent(); break;
            case 'getStructure': (new ExternalApiController())->getStructure(); break;
            default:
                jsonResponse(['error' => 'Action non trouvée'], 404);
        }
    } else {
        jsonResponse(['error' => 'Route non trouvée'], 404);
    }
} catch (Throwable $e) {
    jsonResponse(['error' => 'Erreur serveur', 'message' => $e->getMessage()], 500);
}
