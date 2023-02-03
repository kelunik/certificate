<?php /** @noinspection PhpUnhandledExceptionInspection */

namespace Kelunik\Certificate;

use PHPUnit\Framework\TestCase;

class CertificateTest extends TestCase
{
    public function testCommon()
    {
        $raw = \file_get_contents(__DIR__ . "/data/kelunik.com.pem");
        $cert = new Certificate($raw);

        $this->assertSame("0x01F2C3B8370988B331131E08ACD5CE10071F", $cert->getSerialNumber());
        $this->assertSame("US", $cert->getIssuer()->getCountry());
        $this->assertSame("Let's Encrypt", $cert->getIssuer()->getOrganizationName());
        $this->assertSame("Let's Encrypt Authority X1", $cert->getIssuer()->getCommonName());
        $this->assertFalse($cert->isSelfSigned());
        $this->assertSame(\trim($raw), \trim((string) $cert));
        $this->assertSame(\trim($raw), \trim($cert->toPem()));
        $this->assertSame(\trim($raw), \trim(Certificate::derToPem($cert->toDer())));
        $this->assertSame([
            "commonName" => "www.kelunik.com",
            "names" => ["kelunik.com", "www.kelunik.com"],
            "issuedBy" => "Let's Encrypt Authority X1",
            "validFrom" => \date("d.m.Y", 1445636100),
            "validTo" => \date("d.m.Y", 1453412100),
        ], $cert->__debugInfo());
    }

    public function testLocal()
    {
        $raw = \file_get_contents(__DIR__ . "/data/localhost.pem");
        $cert = new Certificate($raw);

        $this->assertSame("localhost", $cert->getSubject()->getCommonName());
        $this->assertTrue($cert->isSelfSigned());
    }

    public function testSignature()
    {
        $raw = \file_get_contents(__DIR__ . "/data/kelunik.com.pem");
        $cert = new Certificate($raw);

        try {
            $type = $cert->getSignatureType();
            $this->assertSame("RSA-SHA256", $type);
        } catch (FieldNotSupportedException $e) {
            $this->markTestSkipped("Signature type not supported, see https://3v4l.org/Iu3T2");
        }
    }

    public function testDerToPem()
    {
        $pem = \file_get_contents(__DIR__ . "/data/localhost.pem");
        $der = \file_get_contents(__DIR__ . "/data/localhost.der");

        $this->assertSame($der, Certificate::pemToDer($pem));
        $this->assertSame($pem, Certificate::derToPem($der));
    }

    public function testInvalidDerType()
    {
        $this->expectException(\InvalidArgumentException::class);

        Certificate::derToPem(0);
    }

    public function testInvalidPemType()
    {
        $this->expectException(\InvalidArgumentException::class);

        Certificate::pemToDer(0);
    }

    public function testInvalidPem()
    {
        $this->expectException(InvalidCertificateException::class);

        Certificate::pemToDer("");
    }

    public function testNonString()
    {
        $this->expectException(\InvalidArgumentException::class);

        new Certificate(0);
    }

    public function testInvalidPemConstruct()
    {
        $this->expectException(InvalidCertificateException::class);

        new Certificate("");
    }

    public function testPemNormalization()
    {
        $raw = \file_get_contents(__DIR__ . "/data/kelunik.com.pem");
        $modified = \str_replace("-----\n", "-----\n\n", $raw);
        $cert = new Certificate($modified);

        $this->assertNotSame(\trim($raw), \trim($modified));
        $this->assertSame(\trim($raw), \trim($cert->toPem()));
    }
}
