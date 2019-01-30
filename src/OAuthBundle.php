<?php declare(strict_types=1);

namespace Fazland\OAuthBundle;

use Fazland\OAuthBundle\Security\Factory\OAuthFactory;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\HttpKernel\Bundle\Bundle;

class OAuthBundle extends Bundle
{
    /**
     * {@inheritdoc}
     */
    public function build(ContainerBuilder $container): void
    {
        $container->getExtension('security')->addSecurityListenerFactory(new OAuthFactory());
    }
}
