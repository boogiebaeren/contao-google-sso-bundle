<?php

declare(strict_types=1);

namespace BoogieBaeren\ContaoGoogleSsoBundle\Controller;

use Contao\BackendUser;
use Contao\CoreBundle\Controller\AbstractController;
use Contao\CoreBundle\Monolog\ContaoContext;
use Contao\CoreBundle\Security\User\ContaoUserProvider;
use Contao\CoreBundle\Security\User\UserChecker;
use Doctrine\DBAL\Connection;
use Doctrine\DBAL\Exception as DBALException;
use Google\Client;
use Google\Service\Oauth2;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\UriSigner;
use Symfony\Component\PasswordHasher\Hasher\PasswordHasherFactoryInterface;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\AccountStatusException;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class LoginController extends AbstractController
{
    use TargetPathTrait;

    private const SESSION_STATE = 'google_sso_state';
    private const SESSION_NONCE = 'google_sso_nonce';
    private const SESSION_CODE_VERIFIER = 'google_sso_code_verifier';

    private ContaoUserProvider $userProvider;
    private UserChecker $userChecker;
    private string $clientId;

    /**
     * @var list<string>
     */
    private array $allowedDomains;

    private bool $autoCreateUsers;

    /**
     * @param array<string> $allowedDomains
     */
    public function __construct(ContaoUserProvider $userProvider, UserChecker $userChecker, string $clientId, array $allowedDomains, bool $autoCreateUsers = false)
    {
        $this->userProvider = $userProvider;
        $this->userChecker = $userChecker;
        $this->clientId = trim($clientId);
        $this->allowedDomains = array_values(array_filter(array_map(
            static fn (string $domain): string => strtolower(trim($domain)),
            $allowedDomains
        )));
        $this->autoCreateUsers = $autoCreateUsers;
    }

    /**
     * @see \Contao\CoreBundle\Controller\BackendController::loginAction()
     */
    #[Route('/contao/login_sso', name: 'google_sso_login')]
    public function login(Client $client, Request $request, UriSigner $uriSigner): RedirectResponse
    {
        $this->assertConfigured();
        $this->initializeContaoFramework();

        // Keep the original query string order for signature validation.
        $uri = $request->getSchemeAndHttpHost().
            $request->getBaseUrl().
            $request->getPathInfo().
            (null !== ($qs = $request->server->get('QUERY_STRING')) ? '?'.$qs : '');

        $redirect = $request->query->get('redirect');
        $targetPath = null;

        if (\is_string($redirect)) {
            // Login redirects may forward the query signed for Contao's original login route.
            $loginUri = $this->generateUrl('contao_backend_login', [], UrlGeneratorInterface::ABSOLUTE_URL).
                (null !== $qs ? '?'.$qs : '');

            if ($uriSigner->check($uri) || $uriSigner->check($loginUri)) {
                $targetPath = $redirect;
            }
        }

        if ($this->isGranted('IS_AUTHENTICATED_FULLY')) {
            if (null !== $targetPath) {
                return $this->redirect($targetPath);
            }

            return $this->redirectToRoute('contao_backend');
        }

        $session = $request->getSession();

        if (null !== $targetPath) {
            $this->saveTargetPath($session, 'contao_backend', $targetPath);
        }

        $state = bin2hex(random_bytes(32));
        $nonce = bin2hex(random_bytes(32));
        $codeVerifier = rtrim(strtr(base64_encode(random_bytes(64)), '+/', '-_'), '=');

        $session->set(self::SESSION_STATE, $state);
        $session->set(self::SESSION_NONCE, $nonce);
        $session->set(self::SESSION_CODE_VERIFIER, $codeVerifier);

        return $this->redirect($this->googleOAuthUrl($client, $state, $nonce, $codeVerifier));
    }

    /**
     * @throws \Exception
     */
    #[Route('/contao/login_sso/redirect', name: 'google_sso_login_redirect')]
    public function loginAction(
        Client $client,
        Request $request,
        TokenStorageInterface $tokenStorage,
        EventDispatcherInterface $dispatcher,
        LoggerInterface $logger,
        Connection $databaseConnection,
        PasswordHasherFactoryInterface $passwordHasherFactory
    ): Response {
        $this->assertConfigured();

        $client->setRedirectUri($this->generateUrl('google_sso_login_redirect', [], UrlGeneratorInterface::ABSOLUTE_URL));
        $session = $request->getSession();
        $code = $request->query->get('code');

        if (null === $code) {
            // Google Identity Services (one tap / button) posts the ID token directly.
            $idToken = $request->request->get('credential');
            $csrfCookie = $request->cookies->get('g_csrf_token');
            $csrfBody = $request->request->get('g_csrf_token');

            if (!\is_string($csrfCookie) || !\is_string($csrfBody) || '' === $csrfCookie || !hash_equals($csrfCookie, $csrfBody)) {
                throw new \Exception('CSRF token mismatch');
            }

            if (!\is_string($idToken) || '' === $idToken) {
                throw new \Exception('No ID token given');
            }

            $claims = $this->verifyIdToken($client, $idToken, null);
        } else {
            $expectedState = $session->remove(self::SESSION_STATE);
            $expectedNonce = $session->remove(self::SESSION_NONCE);
            $codeVerifier = $session->remove(self::SESSION_CODE_VERIFIER);
            $state = $request->query->get('state');

            if (!\is_string($expectedState) || '' === $expectedState || !\is_string($state) || !hash_equals($expectedState, $state)) {
                throw new \Exception('CSRF token mismatch');
            }

            if (!\is_string($code) || '' === $code || !\is_string($expectedNonce) || !\is_string($codeVerifier)) {
                throw new \Exception('Invalid authorization response');
            }

            $tokenResponse = $client->fetchAccessTokenWithAuthCode($code, $codeVerifier);

            if (!isset($tokenResponse['id_token']) || !\is_string($tokenResponse['id_token'])) {
                $error = isset($tokenResponse['error']) && \is_string($tokenResponse['error']) ? $tokenResponse['error'] : 'unknown';

                throw new \Exception(sprintf('No ID token returned by Google (error: %s)', $error));
            }

            $claims = $this->verifyIdToken($client, $tokenResponse['id_token'], $expectedNonce);
        }

        $email = $this->validatedEmail($claims);
        $name = isset($claims['name']) && \is_string($claims['name']) && '' !== $claims['name'] ? $claims['name'] : $email;

        $userInDb = $databaseConnection->executeQuery(
            'SELECT username FROM tl_user WHERE email = :email',
            ['email' => $email]
        )->fetchAllAssociative();

        if (\count($userInDb) > 1) {
            $logger->log(
                LogLevel::ERROR,
                'Multiple users share the email "'.$email.'", refusing SSO login',
                ['contao' => new ContaoContext(__METHOD__, 'ACCESS')]
            );

            return $this->redirectToRoute('contao_backend');
        }

        if ([] === $userInDb) {
            if (!$this->autoCreateUsers) {
                $logger->log(
                    LogLevel::INFO,
                    'User "'.$email.'" was not found in the database and automatic user creation is disabled',
                    ['contao' => new ContaoContext(__METHOD__, 'ACCESS')]
                );

                return $this->redirectToRoute('contao_backend');
            }

            $logger->log(
                LogLevel::INFO,
                'User "'.$email.'" was not found in the database, creating it',
                ['contao' => new ContaoContext(__METHOD__, 'ACCESS')]
            );

            $username = substr($email, 0, (int) strrpos($email, '@'));
            $this->persistUser($databaseConnection, $passwordHasherFactory, $username, $name, $email, 'de');
        } else {
            if (!\is_string($userInDb[0]['username'] ?? null)) {
                throw new \Exception('Logic error: Username should exist on all users but wasn\'t for '.$email);
            }
            $username = $userInDb[0]['username'];
        }

        $user = $this->userProvider->loadUserByIdentifier($username);

        try {
            $this->userChecker->checkPreAuth($user);
            $this->userChecker->checkPostAuth($user);
        } catch (AccountStatusException $exception) {
            $logger->log(
                LogLevel::INFO,
                'User "'.$email.'" cannot log in via SSO: '.$exception->getMessage(),
                ['contao' => new ContaoContext(__METHOD__, 'ACCESS')]
            );

            return $this->redirectToRoute('contao_backend');
        }

        if ($user->useTwoFactor) {
            $logger->log(
                LogLevel::INFO,
                'User "'.$email.'" has two-factor authentication enabled, falling back to the normal login',
                ['contao' => new ContaoContext(__METHOD__, 'ACCESS')]
            );

            return $this->redirectToRoute('contao_backend');
        }

        $user->loginAttempts = 0;
        $user->lastLogin = $user->currentLogin;
        $user->currentLogin = time();
        $user->save();

        // Prevent session fixation: issue a new session id before authenticating.
        $session->migrate(true);

        $securityToken = new UsernamePasswordToken($user, 'contao_backend', $user->getRoles());
        $tokenStorage->setToken($securityToken);

        $session->set('_security_contao_backend', serialize($securityToken));
        $targetPath = $this->getTargetPath($session, 'contao_backend');
        $this->removeTargetPath($session, 'contao_backend');
        $session->save();

        //Somehow this should be triggered: Contao\CoreBundle\Security\Authentication\AuthenticationSuccessHandler::onAuthenticationSuccess()
        $dispatcher->dispatch(new InteractiveLoginEvent($request, $securityToken), 'security.interactive_login');

        $logger->log(
            LogLevel::INFO,
            'User "'.$email.'" was logged in automatically',
            ['contao' => new ContaoContext(__METHOD__, 'ACCESS')]
        );

        return null !== $targetPath ? $this->redirect($targetPath) : $this->redirectToRoute('contao_backend');
    }

    /**
     * Verifies signature, issuer and expiry (via the Google client) and additionally
     * enforces audience and nonce ourselves, so an empty client id can never disable the check.
     *
     * @return array<mixed>
     */
    private function verifyIdToken(Client $client, string $idToken, ?string $expectedNonce): array
    {
        $claims = $client->verifyIdToken($idToken);

        if (!\is_array($claims)) {
            throw new \Exception('ID token was invalid');
        }

        if (!isset($claims['aud']) || !\is_string($claims['aud']) || !hash_equals($this->clientId, $claims['aud'])) {
            throw new \Exception('ID token was issued for a different client');
        }

        if (null !== $expectedNonce && (!isset($claims['nonce']) || !\is_string($claims['nonce']) || !hash_equals($expectedNonce, $claims['nonce']))) {
            throw new \Exception('ID token nonce mismatch');
        }

        return $claims;
    }

    /**
     * @param array<mixed> $claims
     */
    private function validatedEmail(array $claims): string
    {
        if (true !== ($claims['email_verified'] ?? null)) {
            throw new \Exception('Google account email is not verified');
        }

        $email = $claims['email'] ?? null;

        if (!\is_string($email) || false === filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new \Exception('ID token contains no valid email');
        }

        $email = strtolower($email);
        $emailDomain = substr($email, (int) strrpos($email, '@') + 1);
        $hostedDomain = isset($claims['hd']) && \is_string($claims['hd']) ? strtolower($claims['hd']) : null;

        if (null === $hostedDomain || !\in_array($hostedDomain, $this->allowedDomains, true)) {
            throw new \Exception(sprintf('Google account "%s" does not belong to an allowed Workspace domain', $email));
        }

        if (!\in_array($emailDomain, $this->allowedDomains, true)) {
            throw new \Exception(sprintf('Email domain of "%s" is not allowed', $email));
        }

        return $email;
    }

    private function assertConfigured(): void
    {
        if ('' === $this->clientId || [] === $this->allowedDomains) {
            throw new \LogicException('Google SSO is not configured: client_id and allowed_domains must not be empty');
        }
    }

    private function googleOAuthUrl(Client $client, string $state, string $nonce, string $codeVerifier): string
    {
        $client->setScopes(['openid', Oauth2::USERINFO_EMAIL, Oauth2::USERINFO_PROFILE]);
        $client->setRedirectUri($this->generateUrl('google_sso_login_redirect', [], UrlGeneratorInterface::ABSOLUTE_URL));
        // We only need the identity once, no refresh token.
        $client->setAccessType('online');
        $client->setPrompt('select_account');
        $client->setState($state);

        if (1 === \count($this->allowedDomains)) {
            $client->setHostedDomain($this->allowedDomains[0]);
        }

        return $client->createAuthUrl(null, [
            'nonce' => $nonce,
            'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $codeVerifier, true)), '+/', '-_'), '='),
            'code_challenge_method' => 'S256',
        ]);
    }

    /**
     * @throws DBALException
     * @throws \Exception
     *
     * @see \Contao\CoreBundle\Command\UserCreateCommand::persistUser()
     */
    private function persistUser(Connection $connection, PasswordHasherFactoryInterface $passwordHasherFactory, string $username, string $name, string $email, string $language): void
    {
        // The password is never disclosed; it only has to be unguessable.
        $password = bin2hex(random_bytes(32));
        $time = time();

        $connection->insert('tl_user', [
            'tstamp' => $time,
            'name' => $name,
            'email' => $email,
            'username' => $username,
            'password' => $passwordHasherFactory->getPasswordHasher(BackendUser::class)->hash($password),
            'language' => $language,
            'backendTheme' => 'flexible',
            'admin' => false,
            'pwChange' => false,
            'dateAdded' => $time,
        ]);
    }
}
