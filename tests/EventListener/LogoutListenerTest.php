<?php

declare(strict_types=1);

namespace BoogieBaeren\ContaoGoogleSsoBundle\Tests\EventListener;

use BoogieBaeren\ContaoGoogleSsoBundle\EventListener\LogoutListener;
use Contao\CoreBundle\Routing\ScopeMatcher;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Http\Event\LogoutEvent;

class LogoutListenerTest extends TestCase
{
    /**
     * @dataProvider logoutProvider
     */
    public function testMarksOnlyBackendLogouts(bool $backend, bool $hasResponse, bool $expectCookie): void
    {
        $scopeMatcher = $this->createMock(ScopeMatcher::class);
        $scopeMatcher
            ->method('isBackendRequest')
            ->willReturn($backend)
        ;

        $event = new LogoutEvent(Request::create('https://example.com/contao/logout'), null);
        $response = new RedirectResponse('https://example.com/contao/login');

        if ($hasResponse) {
            $event->setResponse($response);
        }

        (new LogoutListener($scopeMatcher))($event);

        $cookies = array_filter(
            $response->headers->getCookies(),
            static fn (Cookie $cookie): bool => LogoutListener::COOKIE === $cookie->getName() && !$cookie->isCleared(),
        );
        $this->assertSame($expectCookie, [] !== $cookies);
    }

    /**
     * @return array<string, array{bool, bool, bool}>
     */
    public static function logoutProvider(): array
    {
        return [
            'backend logout' => [true, true, true],
            'frontend logout' => [false, true, false],
            'no response to attach it to' => [true, false, false],
        ];
    }
}
