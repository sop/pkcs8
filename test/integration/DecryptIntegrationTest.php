<?php
use Sop\CryptoBridge\Crypto;
use Sop\CryptoEncoding\PEM;
use Sop\CryptoTypes\Asymmetric\PrivateKeyInfo;
use Sop\PKCS8\EncryptedPrivateKeyInfo;

class DecryptIntegrationTest extends PHPUnit_Framework_TestCase
{
    /**
     * @dataProvider provideKey
     *
     * @param string $path
     */
    public function testKey($path)
    {
        $epki = EncryptedPrivateKeyInfo::fromPEM(PEM::fromFile($path));
        $expected = PrivateKeyInfo::fromPEM(
            PEM::fromFile(TEST_ASSETS_DIR . "/pkcs8/private_key.pem"));
        $pki = $epki->decryptWithPassword("password", Crypto::getDefault());
        $this->assertEquals($expected, $pki);
    }
    
    /**
     *
     * @return array
     */
    public function provideKey()
    {
        $dir = TEST_ASSETS_DIR . "/pkcs8";
        return array(
            /* @formatter:off */
            [ "$dir/key_PBE-MD5-DES.pem" ],
            [ "$dir/key_PBE-MD5-RC2-64.pem" ],
            // [ "$dir/key_PBE-SHA1-2DES.pem" ],
            // [ "$dir/key_PBE-SHA1-3DES.pem" ],
            [ "$dir/key_PBE-SHA1-DES.pem" ],
            // [ "$dir/key_PBE-SHA1-RC2-128.pem" ],
            // [ "$dir/key_PBE-SHA1-RC2-40.pem" ],
            [ "$dir/key_PBE-SHA1-RC2-64.pem" ],
            // [ "$dir/key_PBE-SHA1-RC4-128.pem" ],
            // [ "$dir/key_PBE-SHA1-RC4-40.pem" ],
            [ "$dir/key_v2_aes.pem" ],
            [ "$dir/key_v2_des3.pem" ],
            /* @formatter:on */
        );
    }
}
