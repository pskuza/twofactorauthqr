<?php
require 'vendor/autoload.php';

use pskuza\Auth\TwoFactorAuth;


class TwoFactorAuthTest extends PHPUnit_Framework_TestCase
{
    public function testConstructorThrowsOnInvalidDigits() {

        new TwoFactorAuth('Test', 0);
    }

    public function testConstructorThrowsOnInvalidPeriod() {

        new TwoFactorAuth('Test', 6, 0);
    }

    public function testConstructorThrowsOnInvalidAlgorithm() {

        new TwoFactorAuth('Test', 6, 30, 'xxx');
    }

    public function testGetCodeReturnsCorrectResults() {

        $tfa = new TwoFactorAuth('Test');
        $this->assertEquals('543160', $tfa->getCode('VMR466AB62ZBOKHE', 1426847216));
        $this->assertEquals('538532', $tfa->getCode('VMR466AB62ZBOKHE', 0));
    }


    public function testCreateSecretGeneratesDesiredAmountOfEntropy() {
        $rng = new TestRNGProvider(true);

        $tfa = new TwoFactorAuth('Test', 6, 30, 'sha1', null, $rng);
        $this->assertEquals('A', $tfa->createSecret(5));
        $this->assertEquals('AB', $tfa->createSecret(6));
        $this->assertEquals('ABCDEFGHIJKLMNOPQRSTUVWXYZ', $tfa->createSecret(128));
        $this->assertEquals('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', $tfa->createSecret(160));
        $this->assertEquals('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567', $tfa->createSecret(320));
        $this->assertEquals('ABCDEFGHIJKLMNOPQRSTUVWXYZ234567ABCDEFGHIJKLMNOPQRSTUVWXYZ234567A', $tfa->createSecret(321));
    }

    public function testVerifyCodeWorksCorrectly() {

        $tfa = new TwoFactorAuth('Test', 6, 30);
        $this->assertEquals(true , $tfa->verifyCode('VMR466AB62ZBOKHE', '543160', 1, 1426847190));
        $this->assertEquals(true , $tfa->verifyCode('VMR466AB62ZBOKHE', '543160', 0, 1426847190 + 29));	//Test discrepancy
        $this->assertEquals(false, $tfa->verifyCode('VMR466AB62ZBOKHE', '543160', 0, 1426847190 + 30));	//Test discrepancy
        $this->assertEquals(false, $tfa->verifyCode('VMR466AB62ZBOKHE', '543160', 0, 1426847190 - 1));	//Test discrepancy

        $this->assertEquals(true , $tfa->verifyCode('VMR466AB62ZBOKHE', '543160', 1, 1426847205 + 0));	//Test discrepancy
        $this->assertEquals(true , $tfa->verifyCode('VMR466AB62ZBOKHE', '543160', 1, 1426847205 + 35));	//Test discrepancy
        $this->assertEquals(true , $tfa->verifyCode('VMR466AB62ZBOKHE', '543160', 1, 1426847205 - 35));	//Test discrepancy

        $this->assertEquals(false, $tfa->verifyCode('VMR466AB62ZBOKHE', '543160', 1, 1426847205 + 65));	//Test discrepancy
        $this->assertEquals(false, $tfa->verifyCode('VMR466AB62ZBOKHE', '543160', 1, 1426847205 - 65));	//Test discrepancy

        $this->assertEquals(true , $tfa->verifyCode('VMR466AB62ZBOKHE', '543160', 2, 1426847205 + 65));	//Test discrepancy
        $this->assertEquals(true , $tfa->verifyCode('VMR466AB62ZBOKHE', '543160', 2, 1426847205 - 65));	//Test discrepancy
    }

    public function testTotpUriIsCorrect() {
        $qr = new TestQrProvider();

        $tfa = new TwoFactorAuth('Test&Issuer', 6, 30, 'sha1', $qr);
        $data = $this->DecodeDataUri($tfa->getQRCodeImageAsDataUri('Test&Label', 'VMR466AB62ZBOKHE'));
        $this->assertEquals('test/test', $data['mimetype']);
        $this->assertEquals('base64', $data['encoding']);
        $this->assertEquals('otpauth://totp/Test%26Label?secret=VMR466AB62ZBOKHE&issuer=Test%26Issuer&period=30&algorithm=SHA1&digits=6@200', $data['data']);
    }

    public function testGetQRCodeImageAsDataUriThrowsOnInvalidSize() {
        $qr = new TestQrProvider();

        $tfa = new TwoFactorAuth('Test', 6, 30, 'sha1', $qr);
        $tfa->getQRCodeImageAsDataUri('Test', 'VMR466AB62ZBOKHE', 0);
    }

    public function testGetCodeThrowsOnInvalidBase32String1() {
        $tfa = new TwoFactorAuth('Test');
        $tfa->getCode('FOO1BAR8BAZ9');    //1, 8 & 9 are invalid chars
    }

    public function testGetCodeThrowsOnInvalidBase32String2() {
        $tfa = new TwoFactorAuth('Test');
        $tfa->getCode('mzxw6===');        //Lowercase
    }


    public function testKnownTestVectors_sha1() {
        //Known test vectors for SHA1: https://tools.ietf.org/html/rfc6238#page-15
        $secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';   //== base32encode('12345678901234567890')
        $tfa = new TwoFactorAuth('Test', 8, 30, 'sha1');
        $this->assertEquals('94287082', $tfa->getCode($secret, 59));
        $this->assertEquals('07081804', $tfa->getCode($secret, 1111111109));
        $this->assertEquals('14050471', $tfa->getCode($secret, 1111111111));
        $this->assertEquals('89005924', $tfa->getCode($secret, 1234567890));
        $this->assertEquals('69279037', $tfa->getCode($secret, 2000000000));
        $this->assertEquals('65353130', $tfa->getCode($secret, 20000000000));
    }

    public function testKnownTestVectors_sha256() {
        //Known test vectors for SHA256: https://tools.ietf.org/html/rfc6238#page-15
        $secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA';   //== base32encode('12345678901234567890123456789012')
        $tfa = new TwoFactorAuth('Test', 8, 30, 'sha256');
        $this->assertEquals('46119246', $tfa->getCode($secret, 59));
        $this->assertEquals('68084774', $tfa->getCode($secret, 1111111109));
        $this->assertEquals('67062674', $tfa->getCode($secret, 1111111111));
        $this->assertEquals('91819424', $tfa->getCode($secret, 1234567890));
        $this->assertEquals('90698825', $tfa->getCode($secret, 2000000000));
        $this->assertEquals('77737706', $tfa->getCode($secret, 20000000000));
    }

    public function testKnownTestVectors_sha512() {
        //Known test vectors for SHA512: https://tools.ietf.org/html/rfc6238#page-15
        $secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA';   //== base32encode('1234567890123456789012345678901234567890123456789012345678901234')
        $tfa = new TwoFactorAuth('Test', 8, 30, 'sha512');
        $this->assertEquals('90693936', $tfa->getCode($secret, 59));
        $this->assertEquals('25091201', $tfa->getCode($secret, 1111111109));
        $this->assertEquals('99943326', $tfa->getCode($secret, 1111111111));
        $this->assertEquals('93441116', $tfa->getCode($secret, 1234567890));
        $this->assertEquals('38618901', $tfa->getCode($secret, 2000000000));
        $this->assertEquals('47863826', $tfa->getCode($secret, 20000000000));
    }

    private function DecodeDataUri($datauri) {
        if (preg_match('/data:(?P<mimetype>[\w\.\-\/]+);(?P<encoding>\w+),(?P<data>.*)/', $datauri, $m) === 1) {
            return array(
                'mimetype' => $m['mimetype'],
                'encoding' => $m['encoding'],
                'data' => base64_decode($m['data'])
            );
        }
        return null;
    }
}
