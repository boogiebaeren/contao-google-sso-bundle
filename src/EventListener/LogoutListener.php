<?php

declare(strict_types=1);

namespace BoogieBaeren\ContaoGoogleSsoBundle\EventListener;

use Contao\CoreBundle\Routing\ScopeMatcher;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\Security\Http\Event\LogoutEvent;

/**
 * Marks a backend logout, so the next SSO login shows Google's account chooser.
 *
 * Without it, select_account: false would sign the user straight back in after a logout.
 * Runs after Contao's LogoutSuccessListener, which sets the redirect to the login page.
 */
class LogoutListener
{
    public const COOKIE = 'contao_google_sso_logged_out';

    private const LIFETIME = 600;

    public function __construct(private readonly ScopeMatcher $scopeMatcher)
    {
    }

    public function __invoke(LogoutEvent $event): void
    {
        $request = $event->getRequest();
        $response = $event->getResponse();

        if (null === $response || !$this->scopeMatcher->isBackendRequest($request)) {
            return;
        }

        $response->headers->setCookie(Cookie::create(self::COOKIE, '1', time() + self::LIFETIME, '/', null, $request->isSecure(), true, false, Cookie::SAMESITE_LAX));
    }
}
