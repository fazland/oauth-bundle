<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\DependencyInjection\CompilerPass;

use Fazland\OAuthBundle\DependencyInjection\Reference as OAuthReference;
use Symfony\Component\DependencyInjection\Compiler\AbstractRecursivePass;
use Symfony\Component\DependencyInjection\Reference;

class ResolveReferencePass extends AbstractRecursivePass
{
    /**
     * {@inheritdoc}
     */
    protected function processValue($value, $isRoot = false)
    {
        if (! $value instanceof OAuthReference) {
            return parent::processValue($value, $isRoot);
        }

        return new Reference((string) $value, $value->getInvalidBehavior());
    }
}
