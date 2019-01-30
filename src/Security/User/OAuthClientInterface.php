<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Security\User;

use Fazland\OAuthBundle\Encryption\KeyPair\KeyPairInterface;
use Symfony\Component\Security\Core\User\UserInterface;

interface OAuthClientInterface extends UserInterface, KeyPairInterface
{
    /**
     * Gets the OAuth client id.
     *
     * @return string
     */
    public function getId(): string;

    /**
     * Gets the OAuth client secret (if any).
     *
     * @return string|null
     */
    public function getSecret(): ?string;

    /**
     * Gets the OAuth client scope.
     * If the current client does not have a scope, implementors MUST return the empty string.
     *
     * @return string
     */
    public function getScope(): string;

    /**
     * Gets the allowed redirect URIs for authorization code flow.
     *
     * @return string[]
     */
    public function getRedirectUris(): array;

    /**
     * Gets the allowed grant types for the current client.
     *
     * @return string[]
     */
    public function getGrantTypes(): array;
}
