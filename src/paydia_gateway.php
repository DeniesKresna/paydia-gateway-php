<?php

require_once __DIR__ . '/helper.php'; // NOTE: use this for debug log. exmple: debug_log('functionname', data);
require_once __DIR__ . '/snap_interface.php';

class PaydiaGateway implements SnapInterface
{
    protected string $snapHost;
    protected string $snapQrUrl;
    protected string $snapTokenUrl;
    protected string $clientId;
    protected string $secretKey;
    protected string $partnerId;
    protected string $channelId;
    protected string $merchantId;
    protected string $privateKeyPath;

    public function __construct()
    {
        // NOTE: this setup the properties of class
        // you can use your own method to define it your way
        $env_path = __DIR__ . '/.env';
        if (!file_exists($env_path)) {
            die('Environment file not found at: ' . $env_path);
        }

        $env = parse_ini_file($env_path, false, INI_SCANNER_RAW);

        $this->snapHost = $env['SNAP_HOST'] ?? '';
        $this->snapQrUrl = $env['SNAP_QR_URL'] ?? '';
        $this->snapTokenUrl = $env['SNAP_TOKEN_URL'] ?? '';
        $this->clientId = $env['CLIENT_ID'] ?? '';
        $this->secretKey = $env['SECRET_KEY'] ?? '';
        $this->partnerId = $env['PARTNER_ID'] ?? '';
        $this->channelId = $env['CHANNEL_ID'] ?? '';
        $this->merchantId = $env['MERCHANT_ID'] ?? '';
        $this->privateKeyPath = __DIR__ . '/pkcs8_rsa_private_key.pem';
    }

    private function getAsymmetricSignature(string $timestamp): string {
        $stringToSign = $this->clientId . '|' . $timestamp;

        $privateKey = file_get_contents($this->privateKeyPath);
        if (!$privateKey) {
            return '';
        }

        $keyResource = openssl_pkey_get_private($privateKey);
        if (!$keyResource) {
            return '';
        }

        $signature = '';
        $success = openssl_sign($stringToSign, $signature, $keyResource, OPENSSL_ALGO_SHA256);
        openssl_free_key($keyResource);

        if (!$success) {
            return '';
        }

        return base64_encode($signature);
    }

    private function getSymmetricSignature(
        string $method = 'POST',
        string $relative_path = '',
        string $token = '',
        array $req_body = [],
        string $timestamp = ''
    ): string {
        $minified_body = json_encode($req_body, JSON_UNESCAPED_SLASHES);
        $hashed_body = strtolower(bin2hex(hash('sha256', $minified_body, TRUE)));

        $string_to_sign = $method . ':' . $relative_path . ':' . $token . ':' . $hashed_body . ':' . $timestamp;

        return base64_encode(hash_hmac('sha512', $string_to_sign, $this->secretKey, true));
    }

    private function createExternalId(): string {
        $date = date('Ymd');
        $timestamp = time();
        $random = '';

        while (strlen($random) < 18) {
            $random .= mt_rand(0, 9);
        }
        $random = substr($random, 0, 18);

        return $date . $timestamp . $random;
    }

    // NOTE: this only for validation. you can use or not. See Line 209
    private function getValidateQrMpmRequestError(array $data): array {
        $errors = [];

        if (!isset($data['partner_reference_no']) || !is_string($data['partner_reference_no']) || trim($data['partner_reference_no']) === '') {
            $errors[] = "partner_reference_no is required and must be a non-empty string";
        }

        if (!isset($data['amount']) || !is_int($data['amount']) || $data['amount'] <= 0) {
            $errors[] = "amount is required and must be a positive integer";
        }

        if (!isset($data['validity_period']) || !is_string($data['validity_period'])) {
            $errors[] = "validity_period is required and must be a string";
        } else {
            $dt = DateTime::createFromFormat('Y-m-d H:i:s', $data['validity_period']);
            $validFormat = $dt && $dt->format('Y-m-d H:i:s') === $data['validity_period'];
            if (!$validFormat) {
                $errors[] = "validity_period must be in 'yyyy-mm-dd hh:ii:ss' format";
            }
        }

        return $errors;
    }

    private function callSnapApi(string $url, array $headers, array $body = [], string $method = 'POST'): array {
        $ch = curl_init();

        curl_setopt($ch, CURLOPT_URL, $this->snapHost . $url);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);

        if ($method === 'POST') {
            curl_setopt($ch, CURLOPT_POST, true);
        } else {
            curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);
        }

        if (!empty($body)) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($body));
        }

        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlError = curl_error($ch);
        curl_close($ch);

        if ($curlError) {
            return [
                'success' => false,
                'http_code' => $httpCode,
                'message' => $curlError ?: 'Snap API request failed'
            ];
        }

        $result = json_decode($response, true);

        if ($httpCode >= 400) {
            return [
                'success' => false,
                'http_code' => $httpCode,
                'message' => $result['responseMessage'],
                'data' => $result
            ];
        }

        return [
            'success' => true,
            'http_code' => $httpCode,
            'data' => $result
        ];
    }

    public function createBearerToken($timestamp): array {
        $asymmetricSign = $this->getAsymmetricSignature($timestamp);
        if ($asymmetricSign === '') {
            return [
                'success' => false,
                'message' => 'calling asymmetricSignature error'
            ];
        }

        $body = ['grantType' => 'client_credentials'];
        $headers = [
            'Content-Type: application/json',
            'X-TIMESTAMP: ' . $timestamp,
            'X-CLIENT-KEY: ' . $this->clientId,
            'X-SIGNATURE: ' . $asymmetricSign,
        ];

        $response = $this->callSnapApi($this->snapTokenUrl, $headers, $body);

        if (!$response['success']) {
            return [
                'success' => false,
                'message' => 'calling generate token error'
            ];
        }

        $result = $response['data'];
        if (!isset($result['responseCode']) || $result['responseCode'] !== '2007300') {
            return [
                'success' => false,
                'message' => $result['responseMessage'] ?? 'Unknown error'
            ];
        }

        return [
            'success' => true,
            'data' => $result['accessToken'],
            'message' => $result['responseMessage']
        ];
    }

    public function createQrMpm(string $partner_reference_no, int $amount, string $validity_period): array {
        // NOTE: this for validate input only, you can skip optionally
        $validation_data = [
            'partner_reference_no'=> $partner_reference_no,
            'amount'=> $amount,
            'validity_period'=> $validity_period
        ];

        $errors = $this->getValidateQrMpmRequestError($validation_data);
        if (!empty($errors)) {
            return [
                'success' => false,
                'message' => implode("; ", $errors)
            ];
        }
        // end of validation

        $timestamp = (new DateTime('now', new DateTimeZone('Asia/Jakarta')))->format('c');

        $token = $this->createBearerToken($timestamp);
        if (!$token['success']) {
            return [
                'success' => false,
                'message' => $token['message']
            ];
        }

        $amountFormatted = number_format($amount, 2, '.', '');

        $validity = DateTime::createFromFormat('Y-m-d H:i:s', $validity_period)
            ->setTimezone(new DateTimeZone('Asia/Jakarta'))
            ->format('c');

        $body = [
            'merchantId' => $this->merchantId,
            'partnerReferenceNo' => $partner_reference_no,
            'amount' => [
                'value' => $amountFormatted,
                'currency' => 'IDR'
            ],
            'validityPeriod' => $validity
        ];

        $signature = $this->getSymmetricSignature(
            "POST",
            $this->snapQrUrl,
            $token['data'],
            $body,
            $timestamp
        );

        $headers = [
            'X-TIMESTAMP: ' . $timestamp,
            'X-PARTNER-ID: ' . $this->partnerId,
            'X-SIGNATURE: ' . $signature,
            'X-EXTERNAL-ID: ' . $this->createExternalId(),
            'CHANNEL-ID: ' . $this->channelId,
            'Content-Type: application/json',
            'Authorization: Bearer ' . $token['data']
        ];

        $response = $this->callSnapApi($this->snapQrUrl, $headers, $body);

        if (!$response['success']) {
            return [
                'success' => false,
                'message' => $response['message']
            ];
        }

        $result = $response['data'];
        if (!isset($result['responseCode']) || $result['responseCode'] !== '2004700') {
            return [
                'success' => false,
                'message' => $result['responseMessage'] ?? 'undefined error'
            ];
        }

        return [
            'success' => true,
            'message' => $result['responseMessage'] ?? 'success',
            'qr_content' => $result['qrContent'],
            'reference_no' => $result['referenceNo'],
            'partner_reference_no' => $result['partnerReferenceNo']
        ];
    }
}
