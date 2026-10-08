<?php
/**
 * CORS Handler - Lista blanca de dominios frontend
 *
 * HTTP_ORIGIN es el dominio desde donde el navegador hace la petición,
 * es decir, el frontend que consume la API, no el servidor de la API.
 *
 * Dominios permitidos:
 *   - https://geoutcdmx.iecm.mx      (producción)
 *   - https://devgeoutcdmx.iecm.mx   (desarrollo)
 */

$allowedOrigins = [
    'https://geoutcdmx.iecm.mx',
    'https://devgeoutcdmx.iecm.mx',
    'https://devportalmgpc.iecm.mx',
    'https://devportalmgpc.iecm.mx',
    'null',
];

$requestOrigin = $_SERVER['HTTP_ORIGIN'] ?? '';

if (in_array($requestOrigin, $allowedOrigins, true)) {
    // Origen válido: emitir headers CORS
    header("Access-Control-Allow-Origin: $requestOrigin");
    header("Vary: Origin");
    header("Access-Control-Allow-Credentials: false");
} elseif (!empty($requestOrigin)) {
    // Tiene origen pero no está en la lista blanca → rechazar
    http_response_code(403);
    header("Content-Type: application/json; charset=UTF-8");
    echo json_encode(["error" => "Origen no permitido"]);
    exit();
}
// Sin HTTP_ORIGIN (curl, Postman, server-to-server) → continúa sin headers CORS

// Métodos y headers explícitos
header("Access-Control-Allow-Methods: GET, POST, PUT, PATCH, DELETE, OPTIONS");
header("Access-Control-Allow-Headers: Content-Type, X-Api-Key, X-Requested-With, Authorization");
header("Access-Control-Max-Age: 3600");
header("Access-Control-Expose-Headers: Content-Length, Content-Type, X-Total-Count, X-Page-Count");

// Responder preflight de inmediato
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(204);
    exit();
}