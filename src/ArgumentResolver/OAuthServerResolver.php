<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\ArgumentResolver;

use Fazland\OAuthBundle\Security\Firewall\OAuthFirewall;
use OAuth2\Server;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Controller\ArgumentValueResolverInterface;
use Symfony\Component\HttpKernel\ControllerMetadata\ArgumentMetadata;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;
use Symfony\Component\Security\Http\FirewallMapInterface;

class OAuthServerResolver implements ArgumentValueResolverInterface
{
    /**
     * @var FirewallMapInterface
     */
    private $firewallMap;

    public function __construct(FirewallMapInterface $firewallMap)
    {
        $this->firewallMap = $firewallMap;
    }

    /**
     * {@inheritdoc}
     */
    public function supports(Request $request, ArgumentMetadata $argument): bool
    {
        if (Server::class !== $argument->getType()) {
            return false;
        }

        return null !== $this->getFirewall($request);
    }

    /**
     * {@inheritdoc}
     */
    public function resolve(Request $request, ArgumentMetadata $argument): iterable
    {
        yield $this->getFirewall($request)->getOAuthServer();
    }

    private function getFirewall(Request $request): ?OAuthFirewall
    {
        [$listeners] = $this->firewallMap->getListeners($request);

        /** @var ListenerInterface $firewall */
        foreach ($listeners as $firewall) {
            if (! $firewall instanceof OAuthFirewall) {
                continue;
            }

            return $firewall;
        }

        return null;
    }
}
