<?php declare(strict_types=1);

namespace Fazland\OAuthBundle\Tests\Fixtures\Token;

use Fazland\OAuthBundle\Tests\Fixtures\AbstractTestKernel;
use Symfony\Component\Config\Loader\LoaderInterface;

class AppKernel extends AbstractTestKernel
{
    /**
     * {@inheritdoc}
     */
    public function registerContainerConfiguration(LoaderInterface $loader): void
    {
        $loader->load(__DIR__.'/config.yaml');
    }

    /**
     * {@inheritdoc}
     */
    public function getCacheDir(): string
    {
        return __DIR__.'/var/cache/'.$this->environment;
    }

    /**
     * {@inheritdoc}
     */
    public function getLogDir(): string
    {
        return __DIR__.'/var/logs';
    }
}
