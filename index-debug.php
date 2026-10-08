<?php
// Habilitar la visualización de errores para depuración
ini_set('display_errors', 1);
error_reporting(E_ALL);

// Configurar tipo de contenido como JSON
header("Content-Type: application/json; charset=UTF-8");

// Información de depuración sobre la solicitud actual
$debug = [
    'server' => [
        'request_uri' => $_SERVER['REQUEST_URI'] ?? 'no disponible',
        'script_name' => $_SERVER['SCRIPT_NAME'] ?? 'no disponible',
        'php_self' => $_SERVER['PHP_SELF'] ?? 'no disponible',
        'document_root' => $_SERVER['DOCUMENT_ROOT'] ?? 'no disponible',
        'request_method' => $_SERVER['REQUEST_METHOD'] ?? 'no disponible',
        'query_string' => $_SERVER['QUERY_STRING'] ?? 'no disponible',
    ],
    'request' => [
        'get' => $_GET,
        'post' => $_POST,
    ],
    'file_paths' => [
        'current_file' => __FILE__,
        'directory' => __DIR__,
        'parent_directory' => dirname(__DIR__),
        'api_config_path' => dirname(__DIR__) . '/config/api_config.php',
        'api_config_exists' => file_exists(dirname(__DIR__) . '/config/api_config.php'),
    ],
    'parsed_url' => parse_url($_SERVER['REQUEST_URI'])
];

// Probar la ruta de la solicitud
$requestUri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$debug['parsed_request_uri'] = $requestUri;

// Probar diferentes rutas base
$basePaths = ['', '/', '/apidata', '/apidata/spatial', '/html'];
$debug['route_tests'] = [];

foreach ($basePaths as $basePath) {
    if (empty($basePath) || strpos($requestUri, $basePath) === 0) {
        $endpoint = empty($basePath) ? $requestUri : substr($requestUri, strlen($basePath));
        $endpoint = rtrim($endpoint, '/');
        $pathParts = explode('/', ltrim($endpoint, '/'));
        
        $debug['route_tests'][$basePath] = [
            'endpoint' => $endpoint,
            'pathParts' => $pathParts,
            'first_segment' => $pathParts[0] ?? 'none'
        ];
    } else {
        $debug['route_tests'][$basePath] = [
            'match' => false,
            'message' => "La ruta de solicitud no comienza con este prefijo"
        ];
    }
}

// Mostrar toda la información de depuración
echo json_encode($debug, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
?>