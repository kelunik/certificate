<?php

namespace Kelunik\Certificate;

class CertificateTest extends \PHPUnit_Framework_TestCase {
    public function testCommon() {
        $raw = file_get_contents(__DIR__ . "/data/kelunik.com.pem");
        $cert = new Certificate($raw);

        $this->assertSame("RSA-SHA256", $cert->getSignatureType());
        $this->assertSame("169720774684715272062536722760177705551647", $cert->getSerialNumber());
        $this->assertSame("US", $cert->getIssuer()->getCountry());
        $this->assertSame("Let's Encrypt", $cert->getIssuer()->getOrganizationName());
        $this->assertSame("Let's Encrypt Authority X1", $cert->getIssuer()->getCommonName());
        $this->assertFalse($cert->isSelfSigned());
        $this->assertSame($raw, (string) $cert);
        $this->assertSame([
            "commonName" => "www.kelunik.com",
            "names" => ["kelunik.com", "www.kelunik.com"],
            "issuedBy" => "Let's Encrypt Authority X1",
            "validFrom" => date("d.m.Y", 1445636100),
            "validTo" => date("d.m.Y", 1453412100),
        ], $cert->__debugInfo());
    }

    public function testLocal() {
        $raw = file_get_contents(__DIR__ . "/data/localhost.pem");
        $cert = new Certificate($raw);

        $this->assertSame("localhost", $cert->getSubject()->getCommonName());
        $this->assertTrue($cert->isSelfSigned());
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testNonString() {
        new Certificate(0);
    }

    /**
     * @expectedException \InvalidArgumentException
     */
    public function testInvalidPem() {
        new Certificate("");
    }
}
