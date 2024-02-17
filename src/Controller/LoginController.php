<?php

declare(strict_types=1);

namespace BoogieBaeren\ContaoGoogleSsoBundle\Controller;

use Contao\BackendUser;
use Contao\CoreBundle\Controller\AbstractController;
use Contao\CoreBundle\Monolog\ContaoContext;
use Contao\CoreBundle\Security\User\ContaoUserProvider;
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
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;

class LoginController extends AbstractController
{
    private ContaoUserProvider $userProvider;
    private string $hostedDomain;

    public function __construct(ContaoUserProvider $userProvider, string $hostedDomain)
    {
        $this->userProvider = $userProvider;
        $this->hostedDomain = $hostedDomain;
    }

    /**
     * @see \Contao\CoreBundle\Controller\BackendController::loginAction()
     */
    #[Route('/contao/login_sso', name: 'google_sso_login')]
    public function login(Client $client, Request $request, UriSigner $uriSigner): RedirectResponse
    {
        $this->initializeContaoFramework();

        if ($this->isGranted('IS_AUTHENTICATED_FULLY')) {
            // We cannot use $request->getUri() here as we want to work with the original URI (no query string reordering)
            $uri = $request->getSchemeAndHttpHost().
                $request->getBaseUrl().
                $request->getPathInfo().
                (null !== ($qs = $request->server->get('QUERY_STRING')) ? '?'.$qs : '');

            if ($request->query->has('redirect') && $uriSigner->check($uri)) {
                return $this->redirect($request->query->get('redirect'));
            }

            return $this->redirectToRoute('contao_backend');
        }

        return $this->redirect($this->googleOAuthUrl($client));
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
        $client->setRedirectUri($this->generateUrl('google_sso_login_redirect', [], UrlGeneratorInterface::ABSOLUTE_URL));
        $code = $request->query->get('code');

        if (!$code) {
            /** @var ?string $id_token */
            $id_token = $request->request->get('credential');

            if ($request->cookies->get('g_csrf_token') !== $request->request->get('g_csrf_token')) {
                throw new \Exception('CSRF token mismatch');
            }

            $payload = $client->verifyIdToken($id_token);

            if (!$payload || $payload['hd'] !== $this->hostedDomain) {
                throw new \Exception('Token was invalid');
            }
            $userinfo = (object) $payload;
        } else {
            $response_token = $client->fetchAccessTokenWithAuthCode($code);

            if (!\array_key_exists('access_token', $response_token)) {
                throw new \Exception(sprintf('No access token token available %s', json_encode($response_token)));
            }

            $client->setAccessToken($response_token);
            $userinfo = (new Oauth2($client))->userinfo->get();
        }

        $userInDb = $databaseConnection->executeQuery(
            'SELECT * FROM tl_user WHERE email = :email',
            [
                'email' => $userinfo->email,
            ]
        )->fetchAssociative();

        if (false === $userInDb) {
            $logger->log(
                LogLevel::INFO,
                'User "'.$userinfo->email.'" was not found in the database',
                ['contao' => new ContaoContext(__METHOD__, 'ACCESS')]
            );
            $username = strtok($userinfo->email, '@');

            if (!$username) {
                throw new \Exception('Email has no @ symbol: '.$userinfo->email);
            }
            $this->persistUser(
                $databaseConnection,
                $passwordHasherFactory,
                $username,
                $userinfo->name,
                $userinfo->email,
                'de'
            );
        } else {
            if (!\array_key_exists('username', $userInDb)) {
                throw new \Exception('Logic error: Username should exist on all users but wasn\'t for '.$userinfo->email);
            }
            $username = (string) $userInDb['username'];
        }

        $session = $request->getSession();

        $user = $this->userProvider->loadUserByIdentifier($username);

        if ($user->locked) {
            $logger->log(
                LogLevel::INFO,
                'User "'.$userinfo->email.'" is locked',
                ['contao' => new ContaoContext(__METHOD__, 'ACCESS')]
            );

            return $this->redirectToRoute('contao_backend');
        }
        $user->loginAttempts = 0;
        $user->lastLogin = $user->currentLogin;
        $user->currentLogin = time();
        $user->save();

        $response_token = new UsernamePasswordToken($user, 'contao_backend', $user->getRoles());
        $tokenStorage->setToken($response_token);

        $session->set('_security_'.'contao_backend', serialize($response_token));
        $session->save();

        //Somehow this should be triggered: Contao\CoreBundle\Security\Authentication\AuthenticationSuccessHandler::onAuthenticationSuccess()
        $dispatcher->dispatch(new InteractiveLoginEvent($request, $response_token), 'security.interactive_login');

        $logger->log(
            LogLevel::INFO,
            'User "'.$userinfo->email.'" was logged in automatically',
            ['contao' => new ContaoContext(__METHOD__, 'ACCESS')]
        );

        return $this->redirectToRoute('contao_backend');
    }

    private function googleOAuthUrl(Client $client): string
    {
        $client->addScope([Oauth2::USERINFO_EMAIL, Oauth2::USERINFO_PROFILE]);
        $client->setRedirectUri($this->generateUrl('google_sso_login_redirect', [], UrlGeneratorInterface::ABSOLUTE_URL));
        // offline access will give you both an access and refresh token so that
        // your app can refresh the access token without user interaction.
        $client->setAccessType('offline');
        $client->setPrompt('select_account');

        return $client->createAuthUrl();
    }

    /**
     * @throws DBALException
     * @throws \Exception
     *
     * @see \Contao\CoreBundle\Command\UserCreateCommand::persistUser()
     */
    private function persistUser(Connection $connection, PasswordHasherFactoryInterface $passwordHasherFactory, string $username, string $name, string $email, string $language): void
    {
        $alphabet = 'abcdefghijklmnopqrstuwxyzABCDEFGHIJKLMNOPQRSTUWXYZ0123456789';
        $password = '';

        for ($i = 0; $i < 8; ++$i) {
            $password .= $alphabet[random_int(0, \strlen($alphabet) - 1)];
        }
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
