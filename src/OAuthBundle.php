<?php declare(strict_types=1);

namespace Fazland\OAuthBundle;

use Fazland\OAuthBundle\DependencyInjection\CompilerPass\CreateClientCommandPass;
use Fazland\OAuthBundle\DependencyInjection\CompilerPass\ResolveReferencePass;
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
        $container
            ->addCompilerPass(new CreateClientCommandPass())
            ->addCompilerPass(new ResolveReferencePass())
            ->getExtension('security')->addSecurityListenerFactory(new OAuthFactory())
        ;
    }
}
