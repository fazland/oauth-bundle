<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Encryption\KeyPair;

use Fazland\OAuthBundle\Enum\SignatureAlgorithm;

/**
 * Define an public/private key pair holder.
 */
interface KeyPairInterface
{
    /**
     * Gets the public key.
     *
     * @return string
     */
    public function getPublicKey(): string;

    /**
     * Gets the private key.
     *
     * @return string
     */
    public function getPrivateKey(): string;

    /**
     * Gets the signature algorithm for the key pair.
     *
     * @return SignatureAlgorithm
     */
    public function getSignatureAlgorithm(): SignatureAlgorithm;

    /**
     * Generates a new pair of keys and set the internal
     * state of the object accordingly.
     */
    public function resetKeyPair(): void;
}
