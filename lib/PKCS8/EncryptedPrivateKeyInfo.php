<?php

namespace Sop\PKCS8;

use ASN1\Type\Constructed\Sequence;
use ASN1\Type\Primitive\OctetString;
use Sop\CryptoBridge\Crypto;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\AlgorithmIdentifier\Feature\EncryptionAlgorithmIdentifier;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\PKCS5\PBEScheme;
use Sop\PKCS5\ASN1\AlgorithmIdentifier\PBEAlgorithmIdentifier;

/**
 * Implements PKCS #8 <i>EncryptedPrivateKeyInfo</i> ASN.1 type.
 *
 * @link https://tools.ietf.org/html/rfc5208#section-6
 */
class EncryptedPrivateKeyInfo
{
    /**
     * Encryption algorithm.
     *
     * @var EncryptionAlgorithmIdentifier $_algo
     */
    protected $_algo;
    
    /**
     * Encrypted data.
     *
     * @var string $_data
     */
    protected $_data;
    
    /**
     * Constructor.
     *
     * @param EncryptionAlgorithmIdentifier $algo
     * @param string $data Ciphertext
     */
    protected function __construct(EncryptionAlgorithmIdentifier $algo, $data)
    {
        $this->_algo = $algo;
        $this->_data = $data;
    }
    
    /**
     * Initialize from ASN.1.
     *
     * @param Sequence $seq
     * @throws \UnexpectedValueException
     * @return self
     */
    public static function fromASN1(Sequence $seq)
    {
        $algo = PBEAlgorithmIdentifier::fromASN1($seq->at(0)->asSequence());
        if (!($algo instanceof EncryptionAlgorithmIdentifier)) {
            throw new \UnexpectedValueException(
                sprintf("Algorithm %s not supported.", $algo->name()));
        }
        $data = $seq->at(1)
            ->asOctetString()
            ->string();
        return new self($algo, $data);
    }
    
    /**
     * Initialize from DER data.
     *
     * @param string $data
     * @return self
     */
    public static function fromDER($data)
    {
        return self::fromASN1(Sequence::fromDER($data));
    }
    
    /**
     * Initialize from PEM.
     *
     * @param PEM $pem
     * @throws \UnexpectedValueException
     * @return self
     */
    public static function fromPEM(PEM $pem)
    {
        if ($pem->type() != PEM::TYPE_ENCRYPTED_PRIVATE_KEY) {
            throw new \UnexpectedValueException("Invalid PEM type.");
        }
        return self::fromDER($pem->data());
    }
    
    /**
     * Get the encryption algorithm.
     *
     * @return EncryptionAlgorithmIdentifier
     */
    public function encryptionAlgorithm()
    {
        return $this->_algo;
    }
    
    /**
     * Get the encrypted private key data.
     *
     * @return string
     */
    public function encryptedData()
    {
        return $this->_data;
    }
    
    /**
     * Get ASN.1 structure.
     *
     * @return Sequence
     */
    public function toASN1()
    {
        return new Sequence($this->_algo->toASN1(), new OctetString($this->_data));
    }
    
    /**
     * Generate DER encoding.
     *
     * @return string
     */
    public function toDER()
    {
        return $this->toASN1()->toDER();
    }
    
    /**
     * Get encrypted private key PEM.
     *
     * @return PEM
     */
    public function toPEM()
    {
        return new PEM(PEM::TYPE_ENCRYPTED_PRIVATE_KEY, $this->toDER());
    }
    
    /**
     * Decrypt PrivateKeyInfo from the encrypted data using password based
     * encryption.
     *
     * @param string $password Password
     * @param Crypto|null $crypto Crypto engine, use default if not set
     * @return PrivateKeyInfo
     */
    public function decryptWithPassword($password, Crypto $crypto = null)
    {
        $ai = $this->_algo;
        if (!($ai instanceof PBEAlgorithmIdentifier)) {
            throw new \RuntimeException(
                sprintf(
                    "Algorithm %s does not support" .
                         " password based encryption.", $ai->name()));
        }
        try {
            $scheme = PBEScheme::fromAlgorithmIdentifier($ai, $crypto);
            $data = $scheme->decrypt($this->_data, $password);
            return PrivateKeyInfo::fromASN1(Sequence::fromDER($data));
        } catch (\RuntimeException $e) {
            throw new \RuntimeException("Failed to decrypt private key.", 0, $e);
        }
    }
    
    /**
     * Initialize by encrypting a PrivateKeyInfo using password based
     * encryption.
     *
     * @param PrivateKeyInfo $pki Private key info
     * @param PBEAlgorithmIdentifier $algo Encryption algorithm
     * @param string $password Password
     * @param Crypto|null $crypto Crypto engine, use default if not set
     * @return self
     */
    public static function encryptWithPassword(PrivateKeyInfo $pki,
        PBEAlgorithmIdentifier $algo, $password, Crypto $crypto = null)
    {
        $scheme = PBEScheme::fromAlgorithmIdentifier($algo, $crypto);
        $ciphertext = $scheme->encrypt($pki->toDER(), $password);
        return new self($algo, $ciphertext);
    }
    
    /**
     * Initialize by encrypting a PrivateKeyInfo using password based encryption
     * with pre-derived key.
     *
     * @param PrivateKeyInfo $pki Private key info
     * @param PBEAlgorithmIdentifier $algo Encryption algorithm
     * @param string $key Key derived from a password
     * @param Crypto|null $crypto Crypto engine, use default if not set
     * @return self
     */
    public static function encryptWithDerivedKey(PrivateKeyInfo $pki,
        PBEAlgorithmIdentifier $algo, $key, Crypto $crypto = null)
    {
        $scheme = PBEScheme::fromAlgorithmIdentifier($algo, $crypto);
        $ciphertext = $scheme->encryptWithKey($pki->toDER(), $key);
        return new self($algo, $ciphertext);
    }
}
