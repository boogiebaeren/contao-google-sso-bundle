<?php

declare(strict_types=1);

namespace BoogieBaeren\ContaoGoogleSsoBundle\Tests\Controller;

use BoogieBaeren\ContaoGoogleSsoBundle\Controller\LoginController;
use Contao\BackendUser;
use Contao\CoreBundle\Security\User\ContaoUserProvider;
use Contao\CoreBundle\Security\User\UserChecker;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Result;
use Google\Client;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\UriSigner;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;

class LoginControllerTest extends TestCase
{
    /**
     * @dataProvider redirectProvider
     */
    public function testLoginPreservesOnlySignedRedirects(bool $signed, bool $authenticated): void
    {
        $target = 'https://example.com/contao?do=article&act=edit&id=42';
        $signer = new UriSigner('test-secret');
        $url = 'https://example.com/contao/login_sso?redirect='.urlencode($target);
        $request = Request::create($signed ? $signer->sign($url) : $url);
        $session = new Session(new MockArraySessionStorage());
        $request->setSession($session);

        $controller = $this->getMockBuilder(LoginController::class)
            ->disableOriginalConstructor()
            ->onlyMethods(['initializeContaoFramework', 'isGranted', 'generateUrl'])
            ->getMock()
        ;
        $controller
            ->method('isGranted')
            ->willReturn($authenticated);
        $controller
            ->method('generateUrl')
            ->willReturnMap([
            ['contao_backend', [], UrlGeneratorInterface::ABSOLUTE_PATH, '/contao'],
            ['google_sso_login_redirect', [], UrlGeneratorInterface::ABSOLUTE_URL, 'https://example.com/contao/login_sso/redirect'],
        ]);

        $response = $controller->login(new Client(), $request, $signer);

        if ($authenticated) {
            $this->assertSame($signed ? $target : '/contao', $response->getTargetUrl());
        } else {
            $this->assertSame($signed ? $target : null, $session->get('_security.contao_backend.target_path'));
            $this->assertStringContainsString('state='.$session->get('google_sso_state'), $response->getTargetUrl());
        }
    }

    /**
     * @return array<array{bool, bool}>
     */
    public static function redirectProvider(): array
    {
        return [[true, false], [false, false], [true, true], [false, true]];
    }

    /**
     * @dataProvider targetProvider
     */
    public function testSuccessfulLoginConsumesSavedTarget(?string $target): void
    {
        $request = Request::create('https://example.com/contao/login_sso/redirect', 'POST', [
            'credential' => 'test-credential',
            'g_csrf_token' => 'test-csrf',
        ], ['g_csrf_token' => 'test-csrf']);
        $session = new Session(new MockArraySessionStorage());
        $request->setSession($session);

        if (null !== $target) {
            $session->set('_security.contao_backend.target_path', $target);
        }

        $user = $this->createMock(BackendUser::class);
        $user
            ->method('getRoles')
            ->willReturn(['ROLE_USER']);
        $user
            ->expects($this->once())
            ->method('save');
        $provider = $this->createMock(ContaoUserProvider::class);
        $provider
            ->method('loadUserByIdentifier')
            ->with('test-user')
            ->willReturn($user);
        $checker = $this->createMock(UserChecker::class);
        $checker
            ->expects($this->once())
            ->method('checkPreAuth')
            ->with($user);

        $controller = $this->getMockBuilder(LoginController::class)
            ->setConstructorArgs([$provider, $checker])
            ->onlyMethods(['generateUrl'])
            ->getMock()
        ;
        $controller
            ->method('generateUrl')
            ->willReturn('/contao');

        $client = $this->createMock(Client::class);
        $client
            ->method('verifyIdToken')
            ->willReturn(['email' => 'test@example.com']);
        $result = $this->createMock(Result::class);
        $result
            ->method('fetchAssociative')
            ->willReturn(['username' => 'test-user']);
        $connection = $this->createMock(Connection::class);
        $connection
            ->method('executeQuery')
            ->willReturn($result);
        $tokens = new TokenStorage();

        $response = $controller->loginAction(
            $client,
            $request,
            $tokens,
            new EventDispatcher(),
            new NullLogger(),
            $connection,
            $this->createMock(PasswordHasherFactoryInterface::class)
        );

        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertSame($target ?? '/contao', $response->getTargetUrl());
        $this->assertFalse($session->has('_security.contao_backend.target_path'));
        $token = $tokens->getToken();
        $this->assertNotNull($token);
        $this->assertSame($user, $token->getUser());
    }

    /**
     * @return array<array{?string}>
     */
    public static function targetProvider(): array
    {
        return [[null], ['https://example.com/contao?do=article&act=edit&id=42']];
    }
}
