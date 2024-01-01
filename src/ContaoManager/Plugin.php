<?php

declare(strict_types=1);

namespace BoogieBaeren\ContaoGoogleSsoBundle\ContaoManager;

use BoogieBaeren\ContaoGoogleSsoBundle\ContaoGoogleSsoBundle;
use Contao\CoreBundle\ContaoCoreBundle;
use Contao\ManagerPlugin\Bundle\BundlePluginInterface;
use Contao\ManagerPlugin\Bundle\Config\BundleConfig;
use Contao\ManagerPlugin\Bundle\Config\ConfigInterface;
use Contao\ManagerPlugin\Bundle\Parser\ParserInterface;
use Contao\ManagerPlugin\Routing\RoutingPluginInterface;
use Symfony\Component\Config\Loader\LoaderResolverInterface;
use Symfony\Component\HttpKernel\KernelInterface;
use Symfony\Component\Routing\RouteCollection;

class Plugin implements BundlePluginInterface, RoutingPluginInterface
{
    /**
     * @throws \Exception
     */
    public function getRouteCollection(LoaderResolverInterface $resolver, KernelInterface $kernel): ?RouteCollection
    {
        $path = __DIR__.'/../Controller';

        $loader = $resolver->resolve($path, 'annotation');
        if (false === $loader) {
            throw new \Exception(sprintf('Could not resolve loader for path "%s"', $path));
        }

        $routecollection = $loader->load($path);
        if (!$routecollection instanceof RouteCollection) {
            throw new \Exception(sprintf('Could not load routes from path "%s"', $path));
        }

        return $routecollection;
    }

    /**
     * @return array<ConfigInterface>
     */
    public function getBundles(ParserInterface $parser): array
    {
        return [
            BundleConfig::create(ContaoGoogleSsoBundle::class)->setLoadAfter([ContaoCoreBundle::class]),
        ];
    }
}
