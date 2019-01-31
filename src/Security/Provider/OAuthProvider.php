<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Security\Provider;

use Fazland\OAuthBundle\Exception\OAuthAuthenticationException;
use Fazland\OAuthBundle\Security\Token\OAuthToken;
use OAuth2\HttpFoundationBridge\Response;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AccountStatusException;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\User\UserCheckerInterface;
use Symfony\Component\Security\Core\User\UserInterface;

class OAuthProvider implements AuthenticationProviderInterface
{
    /**
     * @var UserProviderInterface
     */
    private $userProvider;

    /**
     * @var UserCheckerInterface
     */
    private $userChecker;

    public function __construct(UserProviderInterface $userProvider, UserCheckerInterface $userChecker)
    {
        $this->userProvider = $userProvider;
        $this->userChecker = $userChecker;
    }

    /**
     * {@inheritdoc}
     */
    public function authenticate(TokenInterface $token)
    {
        if (! $this->supports($token)) {
            $ex = new AuthenticationException('Unsupported token');
            $ex->setToken($token);

            throw $ex;
        }

        /** @var OAuthToken $token */
        $tokenData = $token->getToken();
        $user = $this->getUserFromTokenData($tokenData);

        try {
            $this->auth($token, $user, 'checkPreAuth');

            $roles = null !== $user ? $user->getRoles() : [];
            $roles = \array_unique($roles, SORT_REGULAR);

            if (isset($tokenData['scope'])) {
                $roles = \array_map('trim', \explode(',', $tokenData['scope']));
            }

            $token = new OAuthToken($roles);
            $token->setAuthenticated(true);
            $token->setToken($tokenData);
            $token->setUser($user);

            $this->auth($token, $user, 'checkPostAuth');
        } catch (OAuthAuthenticationException $ex) {
            throw new AuthenticationException('OAuth2 authentication failed', 0, $ex);
        }

        return $token;
    }

    /**
     * {@inheritdoc}
     */
    public function supports(TokenInterface $token): bool
    {
        return $token instanceof OAuthToken;
    }

    /**
     * Retrieve a valid user object from OAuth token data.
     *
     * @param array $tokenData
     *
     * @return UserInterface
     *
     * @throws AuthenticationException if no user can be found for this token
     */
    private function getUserFromTokenData(array $tokenData): UserInterface
    {
        $user = $this->userProvider->provide($tokenData);

        if (null === $user) {
            $ex = new OAuthAuthenticationException(Response::HTTP_UNAUTHORIZED, 'access_denied', 'Cannot find user');
            throw new AuthenticationException('OAuth2 authentication failed', 0, $ex);
        }

        return $user;
    }

    /**
     * Call user-checked method and set the user into the token.
     *
     * @param TokenInterface $token
     * @param UserInterface  $user
     * @param string         $method
     */
    private function auth(TokenInterface $token, UserInterface $user, string $method): void
    {
        try {
            $this->userChecker->$method($user);
        } catch (AccountStatusException $ex) {
            throw new OAuthAuthenticationException(
                Response::HTTP_UNAUTHORIZED,
                'access_denied',
                $ex->getMessage()
            );
        }

        $token->setUser($user);
    }
}
