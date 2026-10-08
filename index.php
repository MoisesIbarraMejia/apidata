<?php

// Importante: Asegúrate de que no haya espacios o líneas vacías antes de la etiqueta 
// y que no haya salida de contenido antes de configurar los encabezados HTTP

// Desactivar la visualización de errores en producción
ini_set('display_errors', 0);
error_reporting(0);

// PRIMERO: Incluir CORS antes que cualquier otro header
require_once __DIR__ . '/cors-handler.php';

// DESPUÉS: Configurar headers de seguridad (menos restrictivos)
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: SAMEORIGIN");
header("X-XSS-Protection: 1; mode=block");
header("Referrer-Policy: strict-origin-when-cross-origin");
header("Cache-Control: public, max-age=300");

// FINALMENTE: Configurar tipo de contenido como JSON
header("Content-Type: application/json; charset=UTF-8");

// Permitir únicamente solicitudes GET para asegurar solo lectura
$method = $_SERVER['REQUEST_METHOD'];
$allowedMethods = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'];
if (!in_array($method, $allowedMethods)) {
    sendResponse(405, ["error" => "Método $method no permitido."]);
    exit;
}


// Clase para gestionar la API
class DataAPI {
    private $conn;
    private $apiKey;
    private $config;
    private $apiConfig;

    public function __construct() {
        $this->loadConfig();
        $this->validateApiKey();
        $this->connectToDatabase();
        ini_set('memory_limit', '512M');
        ini_set('max_execution_time', 300);
        if (function_exists('gc_enable')) gc_enable();
    }

    private function loadConfig() {
        $configPath = __DIR__ . '/config/api_config.php';
        if (!file_exists($configPath)) {
            sendResponse(500, ["error" => "Archivo de configuración no encontrado"]);
            exit;
        }
        $this->config = require $configPath;
    }

    private function validateApiKey() {
        $this->apiKey = $_SERVER['HTTP_X_API_KEY'] ?? ($_GET['api_key'] ?? null);
        if (!$this->apiKey) { sendResponse(401, ["error" => "Se requiere una clave API"]); exit; }
        if (!in_array($this->apiKey, $this->config['allowed_api_keys'])) {
            $this->logSecurityEvent("Clave API inválida: " . $this->apiKey);
            sendResponse(403, ["error" => "Clave API inválida"]); exit;
        }
        $this->apiConfig = $this->config['api_keys'][$this->apiKey];
    }

    private function isTableAllowed($tableName) {
        if (!preg_match('/^[a-zA-Z0-9_]+$/', (string)$tableName)) return false;
        return in_array($tableName, $this->apiConfig['allowed_tables']);
    }

    private function getMaxLimit() {
        return $this->apiConfig['max_limit'] ?? $this->config['default_max_limit'];
    }

    private function canWrite() {
        return isset($this->apiConfig['allow_write']) && $this->apiConfig['allow_write'] === true;
    }

    private function getPrimaryKeyColumn($tableName, array $columns) {
        $pk = $this->config['id_columns'][$tableName] ?? 'id';
        return in_array($pk, $columns) ? $pk : ($columns[0] ?? 'id');
    }

    // Columna binaria (BLOB) de una tabla, si tiene una (ej. 'archivos' -> 'contenido')
    private function getBinaryColumn($tableName) {
        return $this->config['binary_columns'][$tableName] ?? null;
    }

    // Columnas "seguras" para SELECT * (excluye la columna binaria si existe)
    private function getReadableColumns($tableName, array $columns) {
        $binaryCol = $this->getBinaryColumn($tableName);
        if ($binaryCol) {
            return array_values(array_filter($columns, fn($c) => $c !== $binaryCol));
        }
        return $columns;
    }

    private function connectToDatabase() {
        try {
            $this->conn = new PDO(
                "mysql:host={$this->config['db_host']};dbname={$this->config['db_name']};charset=utf8mb4",
                $this->config['db_user'], $this->config['db_pass'],
                [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]
            );
        } catch (PDOException $e) {
            $this->logError("Error de conexión: " . $e->getMessage());
            sendResponse(500, ["error" => "Error al conectar con la base de datos"]); exit;
        }
    }

    private function getTableColumns($tableName) {
        try {
            $stmt = $this->conn->prepare("DESCRIBE `$tableName`");
            $stmt->execute();
            return $stmt->fetchAll(PDO::FETCH_COLUMN, 0);
        } catch (PDOException $e) {
            $this->logError("Error al obtener columnas: " . $e->getMessage());
            return [];
        }
    }

    private function logError($m) { if (!empty($this->config['enable_error_log'])) $this->writeLog('api_errors.log', $m); }
    private function logSecurityEvent($m) { if (!empty($this->config['enable_security_log'])) $this->writeLog('security_events.log', $m, true); }
    private function logApiAccess($e, $p) { if (!empty($this->config['enable_access_log'])) $this->writeLog('api_access.log', "[$e] " . json_encode($p)); }

    private function writeLog($fileName, $message, $includeUA = false) {
        $logDir = __DIR__ . '/logs';
        if (!is_dir($logDir)) mkdir($logDir, 0755, true);
        $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $prefix = "[" . date('Y-m-d H:i:s') . "] [$ip]";
        if ($includeUA) $prefix .= " [" . ($_SERVER['HTTP_USER_AGENT'] ?? 'unknown') . "]";
        file_put_contents("$logDir/$fileName", "$prefix $message" . PHP_EOL, FILE_APPEND);
    }

    public function getDatabaseInfo($tableName) {
        if (!$this->isTableAllowed($tableName)) { sendResponse(403, ["error" => "Tabla no permitida"]); return; }
        try {
            $c = $this->conn->prepare("SELECT COUNT(*) as total FROM `$tableName`");
            $c->execute();
            $count = $c->fetch()['total'];
            $s = $this->conn->prepare("SELECT ROUND(((data_length + index_length)/1024/1024),2) AS size_mb FROM information_schema.TABLES WHERE table_schema = DATABASE() AND table_name = :t");
            $s->bindParam(':t', $tableName);
            $s->execute();
            $size = $s->fetch();
            sendResponse(200, ['table' => $tableName, 'total_records' => $count, 'size_mb' => $size['size_mb'] ?? 'unknown', 'max_limit' => $this->getMaxLimit()]);
        } catch (PDOException $e) {
            sendResponse(500, ["error" => "Error al obtener información"]);
        }
    }

    public function getData($tableName, $limit = null, $offset = 0) {
        if (!$tableName) { sendResponse(400, ["error" => "Se requiere especificar una tabla"]); return; }
        if (!$this->isTableAllowed($tableName)) { sendResponse(403, ["error" => "Tabla no permitida"]); return; }
        $maxLimit = $this->getMaxLimit();
        $limit = $limit === null ? $maxLimit : min(abs((int)$limit), $maxLimit);
        $offset = max(abs((int)$offset), 0);
        try {
            $this->logApiAccess('getData', ['table' => $tableName, 'limit' => $limit]);
            $columns = $this->getTableColumns($tableName);
            if (empty($columns)) { sendResponse(500, ["error" => "No se pudo leer la tabla"]); return; }
            $select = implode(',', array_map(fn($c) => "`$c`", $this->getReadableColumns($tableName, $columns)));
            $stmt = $this->conn->prepare("SELECT $select FROM `$tableName` LIMIT :limit OFFSET :offset");
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            $stmt->execute();
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            sendResponse(200, ['table' => $tableName, 'count' => count($results), 'data' => $results]);
        } catch (PDOException $e) {
            $this->logError($e->getMessage());
            sendResponse(500, ["error" => "Error al procesar la consulta"]);
        }
    }

    public function getRecordById($tableName, $recordId) {
        if (!$this->isTableAllowed($tableName)) { sendResponse(403, ["error" => "Tabla no permitida"]); return; }
        try {
            $columns = $this->getTableColumns($tableName);
            if (empty($columns)) { sendResponse(500, ["error" => "No se pudo leer la tabla"]); return; }
            $pk = $this->getPrimaryKeyColumn($tableName, $columns);
            $select = implode(',', array_map(fn($c) => "`$c`", $this->getReadableColumns($tableName, $columns)));
            $stmt = $this->conn->prepare("SELECT $select FROM `$tableName` WHERE `$pk` = :id");
            $stmt->bindParam(':id', $recordId);
            $stmt->execute();
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$row) { sendResponse(404, ["error" => "Registro no encontrado"]); return; }
            sendResponse(200, $row);
        } catch (PDOException $e) {
            sendResponse(500, ["error" => "Error al procesar la consulta"]);
        }
    }

    public function filterData($tableName, $filters) {
        if (!$this->isTableAllowed($tableName)) { sendResponse(403, ["error" => "Tabla no permitida"]); return; }
        $columns = $this->getTableColumns($tableName);
        if (empty($columns)) { sendResponse(500, ["error" => "No se pudo leer la tabla"]); return; }
        $where = []; $bind = []; $fields = [];
        $system = ['limit', 'offset', 'api_key', 'table', 'fields'];
        if (isset($filters['fields'])) {
            foreach (explode(',', $filters['fields']) as $f) { $f = trim($f); if ($f !== '' && in_array($f, $columns)) $fields[] = $f; }
        }
        foreach ($filters as $col => $val) {
            if (in_array($col, $system)) continue;
            if (!preg_match('/^[a-zA-Z0-9_]+$/', (string)$col) || !in_array($col, $columns)) continue;
            if ($val === '' || strtolower((string)$val) === 'null') { $where[] = "`$col` IS NOT NULL"; continue; }
            $where[] = "`$col` = :$col"; $bind[":$col"] = $val;
        }
        $limit = isset($filters['limit']) ? min((int)$filters['limit'], $this->getMaxLimit()) : $this->getMaxLimit();
        $offset = isset($filters['offset']) ? max((int)$filters['offset'], 0) : 0;
        try {
            $select = !empty($fields) ? implode(',', array_map(fn($c) => "`$c`", $fields)) : implode(',', array_map(fn($c) => "`$c`", $this->getReadableColumns($tableName, $columns)));
            $sql = "SELECT $select FROM `$tableName`";
            if ($where) $sql .= " WHERE " . implode(' AND ', $where);
            $sql .= " LIMIT :limit OFFSET :offset";
            $stmt = $this->conn->prepare($sql);
            foreach ($bind as $k => $v) $stmt->bindValue($k, $v);
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            $stmt->execute();
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            sendResponse(200, ['table' => $tableName, 'count' => count($results), 'data' => $results]);
        } catch (PDOException $e) {
            sendResponse(500, ["error" => "Error de filtrado"]);
        }
    }

    // ============================================================
    // Búsqueda dinámica CON filtro previo
    // GET /suggest/{tabla}?campo=nombreUT&q=cen&limit=10&fields=...
    //     &claveDT=5&tipoUT=Urbana   <-- cualquier otro parámetro = filtro exacto (AND)
    // ============================================================
    public function suggestData($tableName, $field, $query, $limit = 10, $fields = null, $extraFilters = []) {
        if (!$this->isTableAllowed($tableName)) {
            sendResponse(403, ["error" => "Tabla no permitida"]);
            return;
        }

        $columns = $this->getTableColumns($tableName);
        if (empty($columns)) {
            sendResponse(500, ["error" => "No se pudo leer la tabla"]);
            return;
        }

        // Seguridad: el campo de búsqueda debe ser una columna real
        if (!$field || !preg_match('/^[a-zA-Z0-9_]+$/', $field) || !in_array($field, $columns)) {
            sendResponse(400, ["error" => "Campo de búsqueda inválido o no existe en la tabla"]);
            return;
        }

        if ($query === null || trim($query) === '') {
            sendResponse(200, ['table' => $tableName, 'count' => 0, 'data' => []]);
            return;
        }

        $maxLimit = $this->getMaxLimit();
        $limit = min(max((int)$limit, 1), min(50, $maxLimit));

        // Columnas a devolver
        $requested = [];
        if ($fields) {
            foreach (explode(',', $fields) as $f) {
                $f = trim($f);
                if ($f !== '' && in_array($f, $columns)) $requested[] = $f;
            }
        }
        $selectColumns = !empty($requested)
            ? implode(',', array_map(fn($c) => "`$c`", $requested))
            : implode(',', array_map(fn($c) => "`$c`", $this->getReadableColumns($tableName, $columns)));

        // Construir filtros adicionales (coincidencia exacta, combinados con AND)
        $whereConditions = ["`$field` LIKE :q"];
        $bindParams = [':q' => '%' . $query . '%'];

        foreach ($extraFilters as $col => $val) {
            if (!preg_match('/^[a-zA-Z0-9_]+$/', (string)$col) || !in_array($col, $columns)) continue;
            if ($col === $field) continue; // no filtres dos veces la misma columna que ya buscas
            if ($val === '' || strtolower((string)$val) === 'null') continue;

            $whereConditions[] = "`$col` = :filtro_$col";
            $bindParams[":filtro_$col"] = $val;
        }

        try {
            $this->logApiAccess('suggestData', ['table' => $tableName, 'field' => $field, 'q' => $query, 'filtros' => $extraFilters]);

            $sql = "SELECT $selectColumns FROM `$tableName` WHERE " . implode(' AND ', $whereConditions) . " ORDER BY `$field` ASC LIMIT :limit";
            $stmt = $this->conn->prepare($sql);
            foreach ($bindParams as $key => $val) {
                $stmt->bindValue($key, $val);
            }
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->execute();

            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);

            sendResponse(200, [
                'table' => $tableName,
                'field' => $field,
                'query' => $query,
                'filtros_aplicados' => $extraFilters,
                'count' => count($results),
                'data' => $results
            ]);

        } catch (PDOException $e) {
            $this->logError("Error en suggestData: " . $e->getMessage());
            sendResponse(500, ["error" => "Error en la búsqueda"]);
        }
    }

    public function searchData($tableName) {
        if (!$this->isTableAllowed($tableName)) { sendResponse(403, ["error" => "Tabla no permitida"]); return; }
        $body = json_decode(file_get_contents('php://input'), true);
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($body)) { sendResponse(400, ["error" => "Body JSON inválido"]); return; }
        $columns = $this->getTableColumns($tableName);
        if (empty($columns)) { sendResponse(500, ["error" => "No se pudo leer la tabla"]); return; }
        $filters = $body['filters'] ?? []; $where = []; $bind = []; $fields = [];
        $op = strtoupper(trim($body['operator'] ?? 'AND'));
        if (!in_array($op, ['AND', 'OR'])) { sendResponse(400, ["error" => "Operador inválido"]); return; }
        if (!empty($body['fields'])) foreach ($body['fields'] as $f) { if (in_array($f, $columns)) $fields[] = $f; }
        foreach ($filters as $col => $val) {
            if (!preg_match('/^[a-zA-Z0-9_]+$/', (string)$col) || !in_array($col, $columns)) { sendResponse(400, ["error" => "Columna inválida: $col"]); return; }
            if (is_array($val)) {
                if (isset($val['min']) && isset($val['max'])) { $where[] = "`$col` BETWEEN :min_$col AND :max_$col"; $bind[":min_$col"] = $val['min']; $bind[":max_$col"] = $val['max']; }
                elseif (array_keys($val) === range(0, count($val) - 1)) {
                    $ph = []; foreach ($val as $i => $v) { $k = ":list_{$col}_{$i}"; $ph[] = $k; $bind[$k] = $v; }
                    $where[] = "`$col` IN (" . implode(',', $ph) . ")";
                } elseif (isset($val['like'])) { $where[] = "`$col` LIKE :like_$col"; $bind[":like_$col"] = '%' . $val['like'] . '%'; }
                elseif (array_key_exists('null', $val)) { $where[] = $val['null'] ? "`$col` IS NULL" : "`$col` IS NOT NULL"; }
            } elseif ($val !== '' && strtolower((string)$val) !== 'null') { $where[] = "`$col` = :$col"; $bind[":$col"] = $val; }
        }
        $limit = isset($body['limit']) ? min((int)$body['limit'], $this->getMaxLimit()) : $this->getMaxLimit();
        $offset = isset($body['offset']) ? max((int)$body['offset'], 0) : 0;
        try {
            $select = !empty($fields) ? implode(',', array_map(fn($c) => "`$c`", $fields)) : implode(',', array_map(fn($c) => "`$c`", $this->getReadableColumns($tableName, $columns)));
            $sql = "SELECT $select FROM `$tableName`";
            if ($where) $sql .= " WHERE " . implode(" $op ", $where);
            $sql .= " LIMIT :limit OFFSET :offset";
            $stmt = $this->conn->prepare($sql);
            foreach ($bind as $k => $v) $stmt->bindValue($k, $v);
            $stmt->bindValue(':limit', $limit, PDO::PARAM_INT);
            $stmt->bindValue(':offset', $offset, PDO::PARAM_INT);
            $stmt->execute();
            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
            sendResponse(200, ['table' => $tableName, 'count' => count($results), 'data' => $results]);
        } catch (PDOException $e) {
            sendResponse(500, ["error" => "Error en búsqueda"]);
        }
    }

    private function resolveWhereClause(?string $recordId, array $body, array $columns, string $pk): ?array {
        if ($recordId !== null) return ['clause' => "`$pk` = :where_val_0", 'params' => [':where_val_0' => $recordId], 'multi' => false];
        if (!empty($body['where'])) {
            $conditions = isset($body['where']['column']) ? [$body['where']] : $body['where'];
            if (!is_array($conditions) || empty($conditions)) { sendResponse(400, ["error" => "'where' inválido"]); return null; }
            $clauses = []; $params = [];
            foreach ($conditions as $i => $c) {
                $col = $c['column'] ?? null; $val = $c['value'] ?? null;
                if (!$col || preg_match('/[^a-zA-Z0-9_]/', $col) || !in_array($col, $columns)) { sendResponse(400, ["error" => "Columna where inválida"]); return null; }
                $k = ":where_val_$i"; $clauses[] = "`$col` = $k"; $params[$k] = $val;
            }
            return ['clause' => implode(' AND ', $clauses), 'params' => $params, 'multi' => true];
        }
        sendResponse(400, ["error" => "Se requiere ID en la URL o 'where' en el body"]);
        return null;
    }

    public function createRecord($tableName) {
        if (!$this->isTableAllowed($tableName)) { sendResponse(403, ["error" => "Tabla no permitida"]); return; }
        if (!$this->canWrite()) { sendResponse(403, ["error" => "Sin permisos de escritura"]); return; }
        $body = json_decode(file_get_contents('php://input'), true);
        if (json_last_error() !== JSON_ERROR_NONE || !is_array($body)) { sendResponse(400, ["error" => "Body JSON inválido"]); return; }
        $props = $body['properties'] ?? $body;
        if (empty($props)) { sendResponse(400, ["error" => "Se requiere al menos un campo"]); return; }
        $columns = $this->getTableColumns($tableName);
        $pk = $this->getPrimaryKeyColumn($tableName, $columns);
        $valid = [];
        foreach ($props as $c => $v) { if ($c === $pk || !in_array($c, $columns) || preg_match('/[^a-zA-Z0-9_ ]/', $c)) continue; $valid[$c] = $v; }
        if (empty($valid)) { sendResponse(400, ["error" => "No hay columnas válidas"]); return; }
        try {
            $cols = []; $ph = []; $bind = [];
            foreach ($valid as $c => $v) { $cols[] = "`$c`"; $ph[] = ":p_$c"; $bind[":p_$c"] = $v; }
            $stmt = $this->conn->prepare("INSERT INTO `$tableName` (" . implode(',', $cols) . ") VALUES (" . implode(',', $ph) . ")");
            foreach ($bind as $k => $v) $stmt->bindValue($k, $v);
            $stmt->execute();
            sendResponse(201, ['message' => 'Registro creado', 'id' => $this->conn->lastInsertId(), 'table' => $tableName]);
        } catch (PDOException $e) {
            sendResponse(500, ["error" => "Error al crear registro: " . $e->getMessage()]);
        }
    }

    public function replaceRecord($tableName, $recordId = null) {
        if (!$this->isTableAllowed($tableName)) { sendResponse(403, ["error" => "Tabla no permitida"]); return; }
        if (!$this->canWrite()) { sendResponse(403, ["error" => "Sin permisos de modificación"]); return; }
        $body = json_decode(file_get_contents('php://input'), true);
        if (json_last_error() !== JSON_ERROR_NONE || empty($body['properties'])) { sendResponse(400, ["error" => "Se requiere 'properties'"]); return; }
        $columns = $this->getTableColumns($tableName);
        $pk = $this->getPrimaryKeyColumn($tableName, $columns);
        $where = $this->resolveWhereClause($recordId, $body, $columns, $pk);
        if ($where === null) return;
        $set = []; $bind = $where['params'];
        foreach ($body['properties'] as $c => $v) { if ($c === $pk || !in_array($c, $columns) || preg_match('/[^a-zA-Z0-9_ ]/', $c)) continue; $set[] = "`$c` = :p_$c"; $bind[":p_$c"] = $v; }
        if (empty($set)) { sendResponse(400, ["error" => "No hay campos válidos"]); return; }
        try {
            $stmt = $this->conn->prepare("UPDATE `$tableName` SET " . implode(',', $set) . " WHERE " . $where['clause']);
            foreach ($bind as $k => $v) $stmt->bindValue($k, $v);
            $stmt->execute();
            $affected = $stmt->rowCount();
            if (!$affected) { sendResponse(404, ["error" => "Sin cambios o no encontrado"]); return; }
            $resp = ['message' => 'Actualizado', 'table' => $tableName, 'affected_rows' => $affected];
            if (!$where['multi']) $resp['id'] = $recordId;
            sendResponse(200, $resp);
        } catch (PDOException $e) {
            sendResponse(500, ["error" => "Error al actualizar: " . $e->getMessage()]);
        }
    }

    public function patchRecord($tableName, $recordId = null) { $this->replaceRecord($tableName, $recordId); }

    public function deleteRecord($tableName, $recordId) {
        if (!$this->isTableAllowed($tableName)) { sendResponse(403, ["error" => "Tabla no permitida"]); return; }
        if (!$this->canWrite()) { sendResponse(403, ["error" => "Sin permisos de eliminación"]); return; }
        $columns = $this->getTableColumns($tableName);
        $pk = $this->getPrimaryKeyColumn($tableName, $columns);
        try {
            $chk = $this->conn->prepare("SELECT `$pk` FROM `$tableName` WHERE `$pk` = :id");
            $chk->bindValue(':id', $recordId);
            $chk->execute();
            if (!$chk->fetch()) { sendResponse(404, ["error" => "No encontrado"]); return; }
            $stmt = $this->conn->prepare("DELETE FROM `$tableName` WHERE `$pk` = :id");
            $stmt->bindValue(':id', $recordId);
            $stmt->execute();
            sendResponse(200, ['message' => 'Eliminado', 'id' => $recordId, 'table' => $tableName]);
        } catch (PDOException $e) {
            sendResponse(500, ["error" => "Error al eliminar"]);
        }
    }

    // ============================================================
    // NUEVO: subir archivo (imagen, PDF, doc, video...) a una tabla
    // POST /upload/{tabla}   multipart/form-data, campo "file"
    // ============================================================
    public function uploadFile($tableName) {
        if (!$this->isTableAllowed($tableName)) { sendResponse(403, ["error" => "Tabla no permitida"]); return; }
        if (!$this->canWrite()) { sendResponse(403, ["error" => "Sin permisos de escritura"]); return; }

        // Acepta tanto un solo archivo (campo "file") como varios (campo "files[]")
        $files = [];
        if (!empty($_FILES['files'])) {
            // Normalizar el array de PHP cuando se suben varios con el mismo nombre de campo
            $count = count($_FILES['files']['name']);
            for ($i = 0; $i < $count; $i++) {
                $files[] = [
                    'name'     => $_FILES['files']['name'][$i],
                    'type'     => $_FILES['files']['type'][$i],
                    'tmp_name' => $_FILES['files']['tmp_name'][$i],
                    'error'    => $_FILES['files']['error'][$i],
                    'size'     => $_FILES['files']['size'][$i],
                ];
            }
        } elseif (!empty($_FILES['file'])) {
            $files[] = $_FILES['file'];
        }

        if (empty($files)) {
            sendResponse(400, ["error" => "Se requiere al menos un archivo en el campo 'file' o 'files[]' (multipart/form-data)"]);
            return;
        }

        $maxSize = $this->config['default_max_upload_size'] ?? (20 * 1024 * 1024);
        $allowed = $this->config['allowed_mime_types'] ?? null;
        $descripcion = $_POST['descripcion'] ?? null;

        $resultados = [];
        $errores = [];

        foreach ($files as $file) {
            if ($file['error'] !== UPLOAD_ERR_OK) {
                $errores[] = ['archivo' => $file['name'], 'error' => "Código de error {$file['error']}"];
                continue;
            }
            if ($file['size'] > $maxSize) {
                $errores[] = ['archivo' => $file['name'], 'error' => "Excede el tamaño máximo (" . round($maxSize / 1024 / 1024, 1) . " MB)"];
                continue;
            }

            $mime = mime_content_type($file['tmp_name']);
            if ($allowed && !in_array($mime, $allowed)) {
                $errores[] = ['archivo' => $file['name'], 'error' => "Tipo no permitido: $mime"];
                continue;
            }

            try {
                $content = file_get_contents($file['tmp_name']);
                $originalName = basename($file['name']);
                $extension = strtolower(pathinfo($originalName, PATHINFO_EXTENSION));

                $stmt = $this->conn->prepare(
                    "INSERT INTO `$tableName` (nombre_original, tipo_mime, extension, tamano_bytes, contenido, descripcion, fecha_subida)
                    VALUES (:nombre, :mime, :ext, :tamano, :contenido, :descripcion, NOW())"
                );
                $stmt->bindValue(':nombre', $originalName);
                $stmt->bindValue(':mime', $mime);
                $stmt->bindValue(':ext', $extension);
                $stmt->bindValue(':tamano', $file['size'], PDO::PARAM_INT);
                $stmt->bindValue(':contenido', $content, PDO::PARAM_LOB);
                $stmt->bindValue(':descripcion', $descripcion);
                $stmt->execute();

                $resultados[] = [
                    'id' => $this->conn->lastInsertId(),
                    'nombre_original' => $originalName,
                    'tipo_mime' => $mime,
                    'tamano_bytes' => $file['size']
                ];
            } catch (PDOException $e) {
                $this->logError("Error subiendo archivo {$file['name']}: " . $e->getMessage());
                $errores[] = ['archivo' => $file['name'], 'error' => 'Error al guardar en la base de datos'];
            }
        }

        $status = empty($resultados) ? 400 : 201;
        sendResponse($status, [
            'message' => count($resultados) . ' archivo(s) subido(s) correctamente',
            'subidos' => $resultados,
            'errores' => $errores
        ]);
    }

    // ============================================================
    // NUEVO: descargar/ver un archivo guardado
    // GET /file/{tabla}/{id}
    // ============================================================
    public function downloadFile($tableName, $id) {
        if (!$this->isTableAllowed($tableName)) { sendResponse(403, ["error" => "Tabla no permitida"]); return; }
        try {
            $stmt = $this->conn->prepare("SELECT nombre_original, tipo_mime, contenido FROM `$tableName` WHERE id = :id");
            $stmt->bindValue(':id', $id, PDO::PARAM_INT);
            $stmt->execute();
            $row = $stmt->fetch(PDO::FETCH_ASSOC);
            if (!$row) { sendResponse(404, ["error" => "Archivo no encontrado"]); return; }

            header('Content-Type: ' . $row['tipo_mime']);
            header('Content-Disposition: inline; filename="' . $row['nombre_original'] . '"');
            header('Content-Length: ' . strlen($row['contenido']));
            echo $row['contenido'];
            exit;
        } catch (PDOException $e) {
            sendResponse(500, ["error" => "Error al leer archivo"]);
        }
    }
}


// Función para enviar respuestas JSON
function sendResponse($statusCode, $data) {
    http_response_code($statusCode);
    echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
}

// Procesar la solicitud
try {
    $api = new DataAPI();

    // Obtener la ruta de la solicitud
    // Obtener la ruta de la solicitud
    $requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

    // quitar carpeta /apidata si existe
    $basePath = '/apidata';

    if (strpos($requestUri, $basePath) === 0) {
        $requestUri = substr($requestUri, strlen($basePath));
    }

    // Remover /index.php del path si existe
    if (strpos($requestUri, '/index.php/') === 0) {
        $endpoint = substr($requestUri, strlen('/index.php'));
    } elseif (strpos($requestUri, '/index.php') === 0) {
        $endpoint = substr($requestUri, strlen('/index.php'));
    } else {
        $endpoint = $requestUri;
    }
    
    // Enrutar la solicitud según el endpoint
    $endpoint = rtrim($endpoint, '/');
    $pathParts = explode('/', ltrim($endpoint, '/'));
    
    switch ($pathParts[0]) {

    case 'data':
        $api->getData($pathParts[1] ?? null, $_GET['limit'] ?? null, $_GET['offset'] ?? 0);
        break;

    case 'record':
        if (empty($pathParts[1]) || empty($pathParts[2])) { sendResponse(400, ["error" => "Se requiere tabla e ID"]); break; }
        $api->getRecordById($pathParts[1], $pathParts[2]);
        break;

    case 'filter':
        if (empty($pathParts[1])) { sendResponse(400, ["error" => "Se requiere tabla"]); break; }
        $filters = $_GET; unset($filters['table']);
        $api->filterData($pathParts[1], $filters);
        break;

    case 'search':
        if (empty($pathParts[1])) { sendResponse(400, ["error" => "Se requiere tabla"]); break; }
        if ($method !== 'POST') { sendResponse(405, ["error" => "Solo POST"]); break; }
        $api->searchData($pathParts[1]);
        break;

    case 'suggest':
        if (empty($pathParts[1])) { sendResponse(400, ["error" => "Se requiere tabla"]); break; }

        // Todo lo que venga en $_GET, excepto los parámetros de control, se toma como filtro extra
        $filtrosExtra = $_GET;
        unset($filtrosExtra['campo'], $filtrosExtra['q'], $filtrosExtra['limit'], $filtrosExtra['fields'], $filtrosExtra['api_key'], $filtrosExtra['table']);

        $api->suggestData(
            $pathParts[1],
            $_GET['campo'] ?? null,
            $_GET['q'] ?? null,
            $_GET['limit'] ?? 10,
            $_GET['fields'] ?? null,
            $filtrosExtra
        );
        break;

    case 'info':
        if (empty($pathParts[1])) { sendResponse(400, ["error" => "Se requiere tabla"]); break; }
        $api->getDatabaseInfo($pathParts[1]);
        break;

    case 'create':
        if (empty($pathParts[1])) { sendResponse(400, ["error" => "Se requiere tabla"]); break; }
        if ($method !== 'POST') { sendResponse(405, ["error" => "Solo POST"]); break; }
        $api->createRecord($pathParts[1]);
        break;

    case 'update':
        if (empty($pathParts[1])) { sendResponse(400, ["error" => "Se requiere tabla"]); break; }
        if ($method !== 'PUT') { sendResponse(405, ["error" => "Solo PUT"]); break; }
        $api->replaceRecord($pathParts[1], $pathParts[2] ?? null);
        break;

    case 'patch':
        if (empty($pathParts[1])) { sendResponse(400, ["error" => "Se requiere tabla"]); break; }
        if ($method !== 'PATCH') { sendResponse(405, ["error" => "Solo PATCH"]); break; }
        $api->patchRecord($pathParts[1], $pathParts[2] ?? null);
        break;

    case 'delete':
        if (empty($pathParts[1]) || empty($pathParts[2])) { sendResponse(400, ["error" => "Se requiere tabla e ID"]); break; }
        if ($method !== 'DELETE') { sendResponse(405, ["error" => "Solo DELETE"]); break; }
        $api->deleteRecord($pathParts[1], $pathParts[2]);
        break;

    // ── NUEVO: subir y descargar archivos ──
    case 'upload':
        if (empty($pathParts[1])) { sendResponse(400, ["error" => "Se requiere tabla"]); break; }
        if ($method !== 'POST') { sendResponse(405, ["error" => "Solo POST"]); break; }
        $api->uploadFile($pathParts[1]);
        break;

    case 'file':
        if (empty($pathParts[1]) || empty($pathParts[2])) { sendResponse(400, ["error" => "Se requiere tabla e ID"]); break; }
        $api->downloadFile($pathParts[1], $pathParts[2]);
        break;

    default:
        sendResponse(404, ["error" => "Endpoint no encontrado", "ruta" => $endpoint]);
        break;
}
} catch (Exception $e) {
    sendResponse(500, ["error" => "Error en la aplicación: " . $e->getMessage()]);
}

?>



