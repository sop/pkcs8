<?php

declare(strict_types = 1);

use PHPUnit\Framework\TestCase;
use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\ObjectIdentifier;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\AES256CBCAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\Cipher\DESEDE3CBCAlgorithmIdentifier;
use Sop\CryptoTypes\AlgorithmIdentifier\GenericAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBES2AlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEWithSHA1AndRC2CBCAlgorithmIdentifier;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBKDF2AlgorithmIdentifier;
use Sop\PKCS5\PBEScheme;
use Sop\PKCS8\EncryptedPrivateKeyInfo;

/**
 * @internal
 */
class EncryptedPrivateKeyInfoTest extends TestCase
{
    const PASSWORD = 'password';

    private static $_pem_pk;

    private static $_pem_v1;

    private static $_pem_v2;

    private static $_pem_v2_aes;

    public static function setUpBeforeClass(): void
    {
        self::$_pem_pk = PEM::fromFile(
            TEST_ASSETS_DIR . '/pkcs8/private_key.pem');
        self::$_pem_v1 = PEM::fromFile(
            TEST_ASSETS_DIR . '/pkcs8/key_PBE-SHA1-RC2-64.pem');
        self::$_pem_v2 = PEM::fromFile(
            TEST_ASSETS_DIR . '/pkcs8/key_v2_des3.pem');
        self::$_pem_v2_aes = PEM::fromFile(
            TEST_ASSETS_DIR . '/pkcs8/key_v2_aes.pem');
    }

    public static function tearDownAfterClass(): void
    {
        self::$_pem_pk = null;
        self::$_pem_v1 = null;
        self::$_pem_v2 = null;
        self::$_pem_v2_aes = null;
    }

    /**
     * @return \Sop\PKCS8\EncryptedPrivateKeyInfo
     */
    public function testFromPEM()
    {
        $epki = EncryptedPrivateKeyInfo::fromPEM(self::$_pem_v1);
        $this->assertInstanceOf(EncryptedPrivateKeyInfo::class, $epki);
        return $epki;
    }

    /**
     * @depends testFromPEM
     *
     * @param EncryptedPrivateKeyInfo $refkey
     */
    public function testCreate(EncryptedPrivateKeyInfo $refkey)
    {
        $ref_algo = PBEAlgorithmIdentifier::fromASN1(
            $refkey->encryptionAlgorithm()->toASN1());
        $salt = $ref_algo->salt();
        $count = $ref_algo->iterationCount();
        $pki = PrivateKeyInfo::fromPEM(self::$_pem_pk);
        $algo = new PBEWithSHA1AndRC2CBCAlgorithmIdentifier($salt, $count);
        $epki = EncryptedPrivateKeyInfo::encryptWithPassword($pki, $algo,
            self::PASSWORD);
        $this->assertInstanceOf(EncryptedPrivateKeyInfo::class, $epki);
        return $epki;
    }

    /**
     * Test that encrypt implementation produces key identical to reference.
     *
     * @depends testFromPEM
     * @depends testCreate
     *
     * @param EncryptedPrivateKeyInfo $epki
     */
    public function testEqualsToRef(EncryptedPrivateKeyInfo $ref,
        EncryptedPrivateKeyInfo $new)
    {
        $this->assertEquals($ref->toDER(), $new->toDER());
    }

    /**
     * @depends testCreate
     *
     * @param EncryptedPrivateKeyInfo $epki
     */
    public function testEncryptedData(EncryptedPrivateKeyInfo $epki)
    {
        $this->assertIsString($epki->encryptedData());
    }

    /**
     * @depends testCreate
     *
     * @param EncryptedPrivateKeyInfo $epki
     */
    public function testDecrypt(EncryptedPrivateKeyInfo $epki)
    {
        $pki = $epki->decryptWithPassword(self::PASSWORD);
        $this->assertInstanceOf(PrivateKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends testCreate
     *
     * @param EncryptedPrivateKeyInfo $epki
     */
    public function testDecryptFail(EncryptedPrivateKeyInfo $epki)
    {
        $this->expectException(\RuntimeException::class);
        $epki->decryptWithPassword('nope');
    }

    /**
     * @depends testCreate
     *
     * @param EncryptedPrivateKeyInfo $epki
     */
    public function testDecryptInvalidAlgo(EncryptedPrivateKeyInfo $epki)
    {
        $epki = clone $epki;
        $refl = new ReflectionClass($epki);
        $prop = $refl->getProperty('_algo');
        $prop->setAccessible(true);
        $prop->setValue($epki, new GenericAlgorithmIdentifier('1.3.6.1.3'));
        $this->expectException(\RuntimeException::class);
        $epki->decryptWithPassword('nope');
    }

    /**
     * @depends testCreate
     *
     * @param EncryptedPrivateKeyInfo $epki
     */
    public function testToPEM(EncryptedPrivateKeyInfo $epki)
    {
        $pem = $epki->toPEM();
        $this->assertInstanceOf(PEM::class, $pem);
        return $pem;
    }

    /**
     * @depends testToPEM
     *
     * @param PEM $pem
     */
    public function testPEMEqualsToRef(PEM $pem)
    {
        $this->assertEquals(self::$_pem_v1, $pem);
    }

    /**
     * @return EncryptedPrivateKeyInfo
     */
    public function testV2FromPEM()
    {
        $epki = EncryptedPrivateKeyInfo::fromPEM(self::$_pem_v2);
        $this->assertInstanceOf(EncryptedPrivateKeyInfo::class, $epki);
        return $epki;
    }

    /**
     * @depends testV2FromPEM
     *
     * @param EncryptedPrivateKeyInfo $refkey
     */
    public function testCreateV2(EncryptedPrivateKeyInfo $refkey)
    {
        $ref_algo = PBEAlgorithmIdentifier::fromASN1(
            $refkey->encryptionAlgorithm()->toASN1());
        $salt = $ref_algo->salt();
        $count = $ref_algo->iterationCount();
        $iv = $ref_algo->esAlgorithmIdentifier()->initializationVector();
        $pki = PrivateKeyInfo::fromPEM(self::$_pem_pk);
        $algo = new PBES2AlgorithmIdentifier(
            new PBKDF2AlgorithmIdentifier($salt, $count),
            new DESEDE3CBCAlgorithmIdentifier($iv));
        $epki = EncryptedPrivateKeyInfo::encryptWithPassword($pki, $algo,
            self::PASSWORD);
        $this->assertInstanceOf(EncryptedPrivateKeyInfo::class, $epki);
        return $epki;
    }

    /**
     * @depends testV2FromPEM
     * @depends testCreateV2
     *
     * @param EncryptedPrivateKeyInfo $ref
     * @param EncryptedPrivateKeyInfo $new
     */
    public function testV2EqualsToRef(EncryptedPrivateKeyInfo $ref,
        EncryptedPrivateKeyInfo $new)
    {
        $this->assertEquals($ref->toDER(), $new->toDER());
    }

    /**
     * @depends testCreateV2
     *
     * @param EncryptedPrivateKeyInfo $epki
     */
    public function testDecryptV2(EncryptedPrivateKeyInfo $epki)
    {
        $pki = $epki->decryptWithPassword(self::PASSWORD);
        $this->assertInstanceOf(PrivateKeyInfo::class, $pki);
        return $pki;
    }

    /**
     * @depends testV2FromPEM
     *
     * @param EncryptedPrivateKeyInfo $ref
     */
    public function testEncryptWithKey(EncryptedPrivateKeyInfo $refkey)
    {
        $ref_algo = PBEAlgorithmIdentifier::fromASN1(
            $refkey->encryptionAlgorithm()->toASN1());
        $pki = PrivateKeyInfo::fromPEM(self::$_pem_pk);
        $salt = $ref_algo->salt();
        $count = $ref_algo->iterationCount();
        $iv = $ref_algo->esAlgorithmIdentifier()->initializationVector();
        $algo = new PBES2AlgorithmIdentifier(
            new PBKDF2AlgorithmIdentifier($salt, $count),
            new DESEDE3CBCAlgorithmIdentifier($iv));
        $scheme = PBEScheme::fromAlgorithmIdentifier($algo);
        $key = $scheme->kdf()->derive(self::PASSWORD, $salt, $count,
            $algo->esAlgorithmIdentifier()
                ->keySize());
        $epki = EncryptedPrivateKeyInfo::encryptWithDerivedKey($pki, $algo, $key);
        $this->assertEquals($refkey->toDER(), $epki->toDER());
    }

    /**
     * @return EncryptedPrivateKeyInfo
     */
    public function testV2AESFromPEM()
    {
        $epki = EncryptedPrivateKeyInfo::fromPEM(self::$_pem_v2_aes);
        $this->assertInstanceOf(EncryptedPrivateKeyInfo::class, $epki);
        return $epki;
    }

    /**
     * @depends testV2AESFromPEM
     *
     * @param EncryptedPrivateKeyInfo $refkey
     */
    public function testCreateV2AES(EncryptedPrivateKeyInfo $refkey)
    {
        $ref_algo = PBEAlgorithmIdentifier::fromASN1(
            $refkey->encryptionAlgorithm()->toASN1());
        $salt = $ref_algo->salt();
        $count = $ref_algo->iterationCount();
        $iv = $ref_algo->esAlgorithmIdentifier()->initializationVector();
        $prf_algo = $ref_algo->kdfAlgorithmIdentifier()->prfAlgorithmIdentifier();
        $pki = PrivateKeyInfo::fromPEM(self::$_pem_pk);
        $algo = new PBES2AlgorithmIdentifier(
            new PBKDF2AlgorithmIdentifier($salt, $count, null, $prf_algo),
            new AES256CBCAlgorithmIdentifier($iv));
        $epki = EncryptedPrivateKeyInfo::encryptWithPassword($pki, $algo,
            self::PASSWORD);
        $this->assertInstanceOf(EncryptedPrivateKeyInfo::class, $epki);
        return $epki;
    }

    /**
     * @depends testV2AESFromPEM
     * @depends testCreateV2AES
     *
     * @param EncryptedPrivateKeyInfo $ref
     * @param EncryptedPrivateKeyInfo $new
     */
    public function testV2AESEqualsToRef(EncryptedPrivateKeyInfo $ref,
        EncryptedPrivateKeyInfo $new)
    {
        $this->assertEquals($ref->toDER(), $new->toDER());
    }

    /**
     * @depends testCreateV2AES
     *
     * @param EncryptedPrivateKeyInfo $epki
     */
    public function testDecryptV2AES(EncryptedPrivateKeyInfo $epki)
    {
        $pki = $epki->decryptWithPassword(self::PASSWORD);
        $this->assertInstanceOf(PrivateKeyInfo::class, $pki);
        return $pki;
    }

    public function testInvalidAlgo()
    {
        $seq = new Sequence(new Sequence(new ObjectIdentifier('1.3.6.1.3')),
            new OctetString(''));
        $this->expectException(\UnexpectedValueException::class);
        EncryptedPrivateKeyInfo::fromASN1($seq);
    }

    public function testInvalidPEMType()
    {
        $pem = new PEM('nope', '');
        $this->expectException(\UnexpectedValueException::class);
        EncryptedPrivateKeyInfo::fromPEM($pem);
    }
}
