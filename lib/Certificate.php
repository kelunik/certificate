<?php

namespace Kelunik\Certificate;

class Certificate {
    private $pem;
    private $info;

    public function __construct($pem) {
        if (!is_string($pem)) {
            throw new \InvalidArgumentException("Invalid variable type: Expected string, got " . gettype($pem));
        }

        if (!$cert = @openssl_x509_read($pem)) {
            throw new \InvalidArgumentException("Invalid PEM encoded certificate!");
        }

        $this->pem = $pem;
        $this->info = openssl_x509_parse($cert);
    }

    public function getCommonName() {
        return $this->info["subject"]["CN"];
    }

    public function getNames() {
        $names = [];
        $san = isset($this->info["extensions"]["subjectAltName"]) ? $this->info["extensions"]["subjectAltName"] : "";

        $parts = array_map("trim", explode(",", $san));

        foreach ($parts as $part) {
            if (stripos($part, "dns:") === 0) {
                $names[] = substr($part, 4);
            }
        }

        $names = array_map("strtolower", $names);
        $names = array_unique($names);

        sort($names);

        return $names;
    }

    public function getIssuerName() {
        return $this->info["issuer"]["CN"];
    }

    public function getIssuerOrganization() {
        return $this->info["issuer"]["O"];
    }

    public function getIssuerCountry() {
        return $this->info["issuer"]["C"];
    }

    public function getSerialNumber() {
        return $this->info["serialNumber"];
    }

    public function getValidFrom() {
        return $this->info["validFrom_time_t"];
    }

    public function getValidTo() {
        return $this->info["validTo_time_t"];
    }

    public function getSignatureType() {
        return $this->info["signatureTypeSN"];
    }

    public function isSelfSigned() {
        return $this->info["subject"] === $this->info["issuer"];
    }

    public function __toString() {
        return $this->pem;
    }

    public function __debugInfo() {
        return [
            "commonName" => $this->getCommonName(),
            "names" => $this->getNames(),
            "validFrom" => date("d.m.Y", $this->getValidFrom()),
            "validTo" => date("d.m.Y", $this->getValidTo()),
        ];
    }
}