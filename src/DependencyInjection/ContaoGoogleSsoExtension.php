<?php

declare(strict_types=1);

namespace BoogieBaeren\ContaoGoogleSsoBundle\DependencyInjection;

use BoogieBaeren\ContaoGoogleSsoBundle\Controller\LoginController;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\YamlFileLoader;
use Symfony\Component\HttpKernel\DependencyInjection\ConfigurableExtension;

class ContaoGoogleSsoExtension extends ConfigurableExtension
{
    /**
     * @param array{client_id: string, client_secret: string, allowed_domains: list<string>, auto_create_users: bool, select_account: bool} $mergedConfig
     *
     * @throws \Exception
     */
    public function loadInternal(array $mergedConfig, ContainerBuilder $container): void
    {
        $loader = new YamlFileLoader($container, new FileLocator(__DIR__.'/../Resources/config'));
        $loader->load('services.yaml');

        $container->getDefinition('google.sso')->replaceArgument('$config', [
            'client_id' => $mergedConfig['client_id'],
            'client_secret' => $mergedConfig['client_secret'],
        ]);

        $controller = $container->getDefinition(LoginController::class);
        $controller->setArgument('$clientId', $mergedConfig['client_id']);
        $controller->setArgument('$allowedDomains', $mergedConfig['allowed_domains']);
        $controller->setArgument('$autoCreateUsers', $mergedConfig['auto_create_users']);
        $controller->setArgument('$selectAccount', $mergedConfig['select_account']);
    }
}
