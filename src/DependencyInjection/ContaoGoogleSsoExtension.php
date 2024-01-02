<?php

declare(strict_types=1);

namespace BoogieBaeren\ContaoGoogleSsoBundle\DependencyInjection;

use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\HttpKernel\DependencyInjection\ConfigurableExtension;

class ContaoGoogleSsoExtension extends ConfigurableExtension
{
    /**
     * @param array{client_id: string, client_secret: string} $mergedConfig
     *
     * @throws \Exception
     */
    public function loadInternal(array $mergedConfig, ContainerBuilder $container): void
    {
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.yaml');

        $definition = $container->getDefinition('google.sso');
        $definition->replaceArgument('$config', $mergedConfig);
    }
}
