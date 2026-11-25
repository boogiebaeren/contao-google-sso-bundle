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
use PHPUnit\Framework\MockObject\MockObject;
use PHPUnit\Framework\TestCase;
use Psr\Log\NullLogger;
use Symfony\Component\EventDispatcher\EventDispatcher;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\Session;
use Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage;
use Symfony\Component\HttpKernel\UriSigner;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage;

class LoginControllerTest extends TestCase
{
    private const CLIENT_ID = 'test-client.apps.googleusercontent.com';
    private const DOMAINS = ['example.com', 'example.org'];

    /**
     * @dataProvider redirectProvider
     */
    public function testLoginPreservesOnlySignedRedirects(bool $signed, bool $authenticated, bool $forwarded): void
    {
        $target = 'https://example.com/contao/preview?page=787';
        $signer = new UriSigner('test-secret');
        $path = $forwarded ? '/contao/login' : '/contao/login_sso';
        $url = 'https://example.com'.$path.'?redirect='.urlencode($target);
        $url = $signed ? $signer->sign($url) : $url;
        $request = Request::create($forwarded ? str_replace('/contao/login?', '/contao/login_sso?', $url) : $url);
        $session = new Session(new MockArraySessionStorage());
        $request->setSession($session);

        $controller = $this->getMockBuilder(LoginController::class)
            ->setConstructorArgs([$this->createMock(ContaoUserProvider::class), $this->createMock(UserChecker::class), self::CLIENT_ID, self::DOMAINS])
            ->onlyMethods(['initializeContaoFramework', 'isGranted', 'generateUrl'])
            ->getMock()
        ;
        $controller
            ->method('isGranted')
            ->willReturn($authenticated)
        ;
        $controller
            ->method('generateUrl')
            ->willReturnMap([
                ['contao_backend', [], UrlGeneratorInterface::ABSOLUTE_PATH, '/contao'],
                ['contao_backend_login', [], UrlGeneratorInterface::ABSOLUTE_URL, 'https://example.com/contao/login'],
                ['google_sso_login_redirect', [], UrlGeneratorInterface::ABSOLUTE_URL, 'https://example.com/contao/login_sso/redirect'],
            ])
        ;

        $response = $controller->login(new Client(['client_id' => self::CLIENT_ID]), $request, $signer);

        if ($authenticated) {
            $this->assertSame($signed ? $target : '/contao', $response->getTargetUrl());
        } else {
            $this->assertSame($signed ? $target : null, $session->get('_security.contao_backend.target_path'));
            $authUrl = $response->getTargetUrl();
            $nonce = $session->get('google_sso_nonce');
            $this->assertIsString($nonce);
            $this->assertStringContainsString('state='.$session->get('google_sso_state'), $authUrl);
            $this->assertStringContainsString('nonce='.$nonce, $authUrl);
            $this->assertStringContainsString('code_challenge_method=S256', $authUrl);
            $this->assertStringContainsString('access_type=online', $authUrl);
            $this->assertStringContainsString('openid', $authUrl);
        }
    }

    /**
     * @dataProvider selectAccountProvider
     */
    public function testAccountChooserCanBeTurnedOff(?bool $selectAccount, bool $expectPrompt): void
    {
        $request = Request::create('https://example.com/contao/login_sso');
        $request->setSession(new Session(new MockArraySessionStorage()));
        $arguments = [$this->createMock(ContaoUserProvider::class), $this->createMock(UserChecker::class), self::CLIENT_ID, self::DOMAINS];

        if (null !== $selectAccount) {
            $arguments[] = false;
            $arguments[] = $selectAccount;
        }

        $controller = $this->getMockBuilder(LoginController::class)
            ->setConstructorArgs($arguments)
            ->onlyMethods(['initializeContaoFramework', 'isGranted', 'generateUrl'])
            ->getMock()
        ;
        $controller
            ->method('isGranted')
            ->willReturn(false)
        ;
        $controller
            ->method('generateUrl')
            ->willReturn('https://example.com/contao/login_sso/redirect')
        ;

        $authUrl = $controller->login(new Client(['client_id' => self::CLIENT_ID]), $request, new UriSigner('test-secret'))->getTargetUrl();

        $this->assertSame($expectPrompt, str_contains($authUrl, 'prompt=select_account'));
        $this->assertStringContainsString('state=', $authUrl);
    }

    /**
     * @return array<string, array{bool|null, bool}>
     */
    public static function selectAccountProvider(): array
    {
        return [
            'default' => [null, true],
            'enabled' => [true, true],
            'disabled' => [false, false],
        ];
    }

    /**
     * @return array<array{bool, bool, bool}>
     */
    public static function redirectProvider(): array
    {
        return [
            [true, false, false],
            [false, false, false],
            [true, true, false],
            [false, true, false],
            [true, false, true],
            [false, false, true],
            [true, true, true],
            [false, true, true],
        ];
    }

    /**
     * @dataProvider targetProvider
     */
    public function testSuccessfulLoginConsumesSavedTarget(?string $target): void
    {
        $request = $this->gisRequest();
        $session = $request->getSession();

        if (null !== $target) {
            $session->set('_security.contao_backend.target_path', $target);
        }

        $response = $this->runLoginAction($request, $this->claims(), true);

        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertSame($target ?? '/contao', $response->getTargetUrl());
        $this->assertFalse($session->has('_security.contao_backend.target_path'));
    }

    /**
     * @return array<array{?string}>
     */
    public static function targetProvider(): array
    {
        return [[null], ['https://example.com/contao?do=article&act=edit&id=42'], ['https://example.com/contao/preview?page=787']];
    }

    public function testSecondDomainCanLogIn(): void
    {
        $this->runLoginAction($this->gisRequest(), $this->claims(['email' => 'test@example.org', 'hd' => 'example.org']), true);
    }

    public function testSessionIdIsRegeneratedOnLogin(): void
    {
        $request = $this->gisRequest();
        $session = $request->getSession();
        $session->start();
        $before = $session->getId();

        $this->runLoginAction($request, $this->claims(), true);

        $this->assertNotSame($before, $session->getId());
    }

    /**
     * @dataProvider csrfProvider
     */
    public function testGisFlowRejectsMissingOrMismatchingCsrfToken(?string $cookie, ?string $body): void
    {
        $post = ['credential' => 'test-credential'];
        $cookies = [];

        if (null !== $body) {
            $post['g_csrf_token'] = $body;
        }

        if (null !== $cookie) {
            $cookies['g_csrf_token'] = $cookie;
        }

        $request = Request::create('https://example.com/contao/login_sso/redirect', 'POST', $post, $cookies);
        $request->setSession(new Session(new MockArraySessionStorage()));

        $this->expectExceptionMessage('CSRF token mismatch');
        $this->runLoginAction($request, $this->claims(), false);
    }

    /**
     * @return array<array{?string, ?string}>
     */
    public static function csrfProvider(): array
    {
        return [[null, null], ['', ''], ['a', null], [null, 'a'], ['a', 'b']];
    }

    public function testCodeFlowRejectsMissingState(): void
    {
        $request = Request::create('https://example.com/contao/login_sso/redirect?code=abc');
        $request->setSession(new Session(new MockArraySessionStorage()));

        $this->expectExceptionMessage('CSRF token mismatch');
        $this->runLoginAction($request, $this->claims(), false);
    }

    /**
     * @dataProvider invalidClaimsProvider
     *
     * @param array<string, mixed> $override
     */
    public function testRejectsInvalidClaims(array $override, string $message): void
    {
        $this->expectExceptionMessage($message);
        $this->runLoginAction($this->gisRequest(), $this->claims($override), false);
    }

    /**
     * @return array<string, array{array<string, mixed>, string}>
     */
    public static function invalidClaimsProvider(): array
    {
        return [
            'foreign audience' => [['aud' => 'other-client.apps.googleusercontent.com'], 'different client'],
            'missing audience' => [['aud' => null], 'different client'],
            'unverified email' => [['email_verified' => false], 'not verified'],
            'missing hd (consumer account)' => [['hd' => null], 'allowed Workspace domain'],
            'foreign hd' => [['hd' => 'evil.com', 'email' => 'test@evil.com'], 'allowed Workspace domain'],
            'email outside allowed domains' => [['email' => 'test@evil.com'], 'Email domain'],
        ];
    }

    public function testEmptyClientIdFailsClosed(): void
    {
        $controller = new LoginController(
            $this->createMock(ContaoUserProvider::class),
            $this->createMock(UserChecker::class),
            '',
            self::DOMAINS
        );

        $this->expectException(\LogicException::class);
        $controller->loginAction(
            $this->createMock(Client::class),
            $this->gisRequest(),
            new TokenStorage(),
            new EventDispatcher(),
            new NullLogger(),
            $this->createMock(Connection::class),
            $this->createMock(PasswordHasherFactoryInterface::class)
        );
    }

    public function testUnknownUserIsNotCreatedByDefault(): void
    {
        $connection = $this->connection([]);
        $connection
            ->expects($this->never())
            ->method('insert')
        ;
        $tokens = new TokenStorage();

        $response = $this->controller(null)->loginAction(
            $this->client($this->claims()),
            $this->gisRequest(),
            $tokens,
            new EventDispatcher(),
            new NullLogger(),
            $connection,
            $this->createMock(PasswordHasherFactoryInterface::class)
        );

        $this->assertInstanceOf(RedirectResponse::class, $response);
        $this->assertNull($tokens->getToken());
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function runLoginAction(Request $request, array $claims, bool $expectLogin): Response
    {
        $user = $this->createMock(BackendUser::class);
        $user
            ->method('getRoles')
            ->willReturn(['ROLE_USER'])
        ;
        $user
            ->expects($expectLogin ? $this->once() : $this->never())
            ->method('save')
        ;

        $tokens = new TokenStorage();
        $response = $this->controller($user)->loginAction(
            $this->client($claims),
            $request,
            $tokens,
            new EventDispatcher(),
            new NullLogger(),
            $this->connection([['username' => 'test-user']]),
            $this->createMock(PasswordHasherFactoryInterface::class)
        );

        if ($expectLogin) {
            $token = $tokens->getToken();
            $this->assertNotNull($token);
            $this->assertSame($user, $token->getUser());
        }

        return $response;
    }

    private function controller(?BackendUser $user): LoginController
    {
        $provider = $this->createMock(ContaoUserProvider::class);

        if (null !== $user) {
            $provider
                ->method('loadUserByIdentifier')
                ->with('test-user')
                ->willReturn($user)
            ;
        }

        $controller = $this->getMockBuilder(LoginController::class)
            ->setConstructorArgs([$provider, $this->createMock(UserChecker::class), self::CLIENT_ID, self::DOMAINS])
            ->onlyMethods(['generateUrl'])
            ->getMock()
        ;
        $controller
            ->method('generateUrl')
            ->willReturn('/contao')
        ;

        return $controller;
    }

    /**
     * @param array<string, mixed> $claims
     */
    private function client(array $claims): Client
    {
        $client = $this->createMock(Client::class);
        $client
            ->method('verifyIdToken')
            ->willReturn($claims)
        ;

        return $client;
    }

    /**
     * @param array<array<string, mixed>> $rows
     *
     * @return Connection&MockObject
     */
    private function connection(array $rows): Connection
    {
        $result = $this->createMock(Result::class);
        $result
            ->method('fetchAllAssociative')
            ->willReturn($rows)
        ;
        $connection = $this->createMock(Connection::class);
        $connection
            ->method('executeQuery')
            ->willReturn($result)
        ;

        return $connection;
    }

    /**
     * @param array<string, mixed> $override
     *
     * @return array<string, mixed>
     */
    private function claims(array $override = []): array
    {
        return array_filter(array_merge([
            'iss' => 'https://accounts.google.com',
            'aud' => self::CLIENT_ID,
            'email' => 'test@example.com',
            'email_verified' => true,
            'hd' => 'example.com',
            'name' => 'Test User',
        ], $override), static fn ($v) => null !== $v);
    }

    private function gisRequest(): Request
    {
        $request = Request::create('https://example.com/contao/login_sso/redirect', 'POST', [
            'credential' => 'test-credential',
            'g_csrf_token' => 'test-csrf',
        ], ['g_csrf_token' => 'test-csrf']);
        $request->setSession(new Session(new MockArraySessionStorage()));

        return $request;
    }
}
