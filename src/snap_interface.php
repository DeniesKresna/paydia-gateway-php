<?php

interface SnapInterface {
    public function createQrMpm(string $partner_reference_no, int $amount, string $validity_period): array;
    public function createBearerToken($timestamp): array;
}