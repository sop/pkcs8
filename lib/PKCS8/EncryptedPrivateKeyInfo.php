<?php

declare(strict_types = 1);

namespace Sop\PKCS8;

use Sop\ASN1\Type\Constructed\Sequence;
use Sop\ASN1\Type\Primitive\OctetString;
use Sop\ASN1\Type\UnspecifiedType;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\EncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEAlgorithmIdentifier;
use Sop\PKCS5\PBEScheme;

/**
 * Implements PKCS #8 *EncryptedPrivateKeyInfo* ASN.1 type.
 *
 * @see https://tools.ietf.org/html/rfc5208#section-6
 */
class EncryptedPrivateKeyInfo
{
    /**
     * Encryption algorithm.
     *
     * @var EncryptionAlgorithmIdentifier
     */
    protected $_algo;

    /**
     * Encrypted data.
     *
     * @var string
     */
    protected $_data;

    /**
     * Constructor.
     *
     * @param EncryptionAlgorithmIdentifier $algo
     * @param string                        $data Ciphertext
     */
    protected function __construct(EncryptionAlgorithmIdentifier $algo, string $data)
    {
        $this->_algo = $algo;
        $this->_data = $data;
    }

    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     *
     * @throws \UnexpectedValueException
     *
     * @return self
     */
    public static function fromASN1(Sequence $seq): self
    {
        $algo = PBEAlgorithmIdentifier::fromASN1($seq->at(0)->asSequence());
        if (!($algo instanceof EncryptionAlgorithmIdentifier)) {
            throw new \UnexpectedValueException(
                sprintf('Algorithm %s not supported.', $algo->name()));
        }
        $data = $seq->at(1)->asOctetString()->string();
        return new self($algo, $data);
    }

    /**
     * Initialize from DER data.
     *
     * @param string $data
     *
     * @return self
     */
    public static function fromDER(string $data): self
    {
        return self::fromASN1(UnspecifiedType::fromDER($data)->asSequence());
    }

    /**
     * Initialize from PEM.
     *
     * @param PEM $pem
     *
     * @throws \UnexpectedValueException
     *
     * @return self
     */
    public static function fromPEM(PEM $pem): self
    {
        if (PEM::TYPE_ENCRYPTED_PRIVATE_KEY !== $pem->type()) {
            throw new \UnexpectedValueException('Invalid PEM type.');
        }
        return self::fromDER($pem->data());
    }

    /**
     * Get the encryption algorithm.
     *
     * @return EncryptionAlgorithmIdentifier
     */
    public function encryptionAlgorithm(): EncryptionAlgorithmIdentifier
    {
        return $this->_algo;
    }

    /**
     * Get the encrypted private key data.
     *
     * @return string
     */
    public function encryptedData(): string
    {
        return $this->_data;
    }

    /**
     * Get ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1(): Sequence
    {
        return new Sequence($this->_algo->toASN1(), new OctetString($this->_data));
    }

    /**
     * Generate DER encoding.
     *
     * @return string
     */
    public function toDER(): string
    {
        return $this->toASN1()->toDER();
    }

    /**
     * Get encrypted private key PEM.
     *
     * @return PEM
     */
    public function toPEM(): PEM
    {
        return new PEM(PEM::TYPE_ENCRYPTED_PRIVATE_KEY, $this->toDER());
    }

    /**
     * Decrypt PrivateKeyInfo from the encrypted data using password based encryption.
     *
     * @param string      $password Password
     * @param null|Crypto $crypto   Crypto engine, use default if not set
     *
     * @return PrivateKeyInfo
     */
    public function decryptWithPassword(string $password, ?Crypto $crypto = null): PrivateKeyInfo
    {
        $ai = $this->_algo;
        if (!($ai instanceof PBEAlgorithmIdentifier)) {
            throw new \RuntimeException(
                sprintf('Algorithm %s does not support' .
                    ' password based encryption.', $ai->name()));
        }
        try {
            $scheme = PBEScheme::fromAlgorithmIdentifier($ai, $crypto);
            $data = $scheme->decrypt($this->_data, $password);
            return PrivateKeyInfo::fromASN1(
                UnspecifiedType::fromDER($data)->asSequence());
        } catch (\RuntimeException $e) {
            throw new \RuntimeException('Failed to decrypt private key.', 0, $e);
        }
    }

    /**
     * Initialize by encrypting a PrivateKeyInfo using password based encryption.
     *
     * @param PrivateKeyInfo         $pki      Private key info
     * @param PBEAlgorithmIdentifier $algo     Encryption algorithm
     * @param string                 $password Password
     * @param null|Crypto            $crypto   Crypto engine, use default if not set
     *
     * @return self
     */
    public static function encryptWithPassword(PrivateKeyInfo $pki,
        PBEAlgorithmIdentifier $algo, string $password, ?Crypto $crypto = null): self
    {
        $scheme = PBEScheme::fromAlgorithmIdentifier($algo, $crypto);
        $ciphertext = $scheme->encrypt($pki->toDER(), $password);
        return new self($algo, $ciphertext);
    }

    /**
     * Initialize by encrypting a PrivateKeyInfo using password based encryption
     * with pre-derived key.
     *
     * @param PrivateKeyInfo         $pki    Private key info
     * @param PBEAlgorithmIdentifier $algo   Encryption algorithm
     * @param string                 $key    Key derived from a password
     * @param null|Crypto            $crypto Crypto engine, use default if not set
     *
     * @return self
     */
    public static function encryptWithDerivedKey(PrivateKeyInfo $pki,
        PBEAlgorithmIdentifier $algo, string $key, ?Crypto $crypto = null): self
    {
        $scheme = PBEScheme::fromAlgorithmIdentifier($algo, $crypto);
        $ciphertext = $scheme->encryptWithKey($pki->toDER(), $key);
        return new self($algo, $ciphertext);
    }
}
