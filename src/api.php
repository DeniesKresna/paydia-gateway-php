<?php

require_once __DIR__ . '/paydia_gateway.php';

header('Content-Type: application/json');

try {
    $inputJson = file_get_contents('php://input');
    $input = json_decode($inputJson, true);

    if (json_last_error() !== JSON_ERROR_NONE) {
        http_response_code(400);
        echo json_encode([
            "success" => false,
            "message" => "Invalid JSON input"
        ]);
        exit;
    }

    $gateway = new PaydiaGateway();
    $result = $gateway->createQrMpm($input['partner_reference_no'], $input['amount'], $input['validity_period']);

    http_response_code($result['success'] ? 200 : 400);
    echo json_encode($result);
} catch (Throwable $e) {
    http_response_code(500);
    echo json_encode([
        "success" => false,
        "message" => "Internal server error",
        "error" => $e->getMessage()
    ]);
}
