<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Encryption\KeyPair;

use Fazland\OAuthBundle\Enum\SignatureAlgorithm;

/**
 * Trait for common implementation of the KeyPairInterface.
 */
trait KeyPairTrait
{
    /**
     * @var string
     */
    private $privateKey;

    /**
     * @var string
     */
    private $publicKey;

    /**
     * @var SignatureAlgorithm
     */
    private $signatureAlgorithm;

    /**
     * {@inheritdoc}
     */
    public function getPublicKey(): string
    {
        return $this->publicKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }

    /**
     * {@inheritdoc}
     */
    public function getSignatureAlgorithm(): SignatureAlgorithm
    {
        return $this->signatureAlgorithm;
    }

    /**
     * {@inheritdoc}
     */
    public function resetKeyPair(): void
    {
        $resource = \openssl_pkey_new([
            'curve_name' => 'secp521r1',
            'private_key_type' => OPENSSL_KEYTYPE_EC,
        ]);

        \openssl_pkey_export($resource, $priKey);
        $pubKey = \openssl_pkey_get_details($resource)['key'];

        $this->signatureAlgorithm = SignatureAlgorithm::ES512();
        $this->privateKey = $priKey;
        $this->publicKey = $pubKey;
    }
}
