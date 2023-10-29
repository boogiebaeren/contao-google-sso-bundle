<?php

namespace BoogieBaeren\ContaoGoogleSsoBundle\Controller;

use Contao\BackendUser;
use Contao\CoreBundle\Controller\AbstractController;
use Contao\CoreBundle\Framework\ContaoFramework;
use Contao\CoreBundle\Monolog\ContaoContext;
use Contao\CoreBundle\Security\User\ContaoUserProvider;
use Doctrine\DBAL\Connection;
use Exception;
use Google\Client;
use Google\Service\Oauth2;
use Psr\Log\LoggerInterface;
use Psr\Log\LogLevel;
use Symfony\Component\EventDispatcher\EventDispatcherInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface;
use Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken;
use Symfony\Component\Security\Core\Exception\UsernameNotFoundException;
use Symfony\Component\Security\Http\Event\InteractiveLoginEvent;

class LoginController extends AbstractController
{

    /**
     * @Route("/contao/login_sso", name="login")
     */
    public function login(Request $request): RedirectResponse
    {
        $this->initializeContaoFramework();

        if ($this->isGranted('IS_AUTHENTICATED_FULLY')) {
            if ($request->query->has('redirect')) {
                $uriSigner = $this->container->get('uri_signer');

                // We cannot use $request->getUri() here as we want to work with the original URI (no query string reordering)
                if ($uriSigner->check($request->getSchemeAndHttpHost().$request->getBaseUrl().$request->getPathInfo().(null !== ($qs = $request->server->get('QUERY_STRING')) ? '?'.$qs : ''))) {
                    return new RedirectResponse($request->query->get('redirect'));
                }
            }

            return new RedirectResponse($this->generateUrl('contao_backend'));
        }

        $client = new Client();
        $client->setClientId($_ENV['GOOGLE_SSO_CLIENTID']);
        $client->setClientSecret($_ENV['GOOGLE_SSO_CLIENTSECRET']);
        $client->addScope([Oauth2::USERINFO_EMAIL, Oauth2::USERINFO_PROFILE]);
        $client->setRedirectUri($this->generateUrl('login_redirect', [], UrlGeneratorInterface::ABSOLUTE_URL));
        // offline access will give you both an access and refresh token so that
        // your app can refresh the access token without user interaction.
        $client->setAccessType('offline');
        $client->setPrompt('select_account');
        $auth_url = $client->createAuthUrl();
        return $this->redirect($auth_url);
    }

    /**
     * @Route("/contao/login_sso/redirect", name="login_redirect")
     *
     * @throws \Exception
     */
    public function loginAction(
      Request $request,
      ContaoFramework $framework,
      TokenStorageInterface $tokenStorage,
      EventDispatcherInterface $dispatcher,
      LoggerInterface $logger,
      RequestStack $requestStack,
      Connection $databaseConnection
    ): Response {
        $client = new Client();
        $client->setClientId($_ENV['GOOGLE_SSO_CLIENTID']);
        $client->setClientSecret($_ENV['GOOGLE_SSO_CLIENTSECRET']);
        $client->setRedirectUri($this->generateUrl('login_redirect', [], UrlGeneratorInterface::ABSOLUTE_URL));
        $response_token = $client->fetchAccessTokenWithAuthCode($request->query->get('code'));
        if (!key_exists('access_token', $response_token)) {
            throw new \Exception(sprintf("No access token token available %s", json_encode($response_token)));
        }

        $client->setAccessToken($response_token);
        $oauth2 = new Oauth2($client);
        $userinfo = $oauth2->userinfo->get();

        $userInDb = $databaseConnection->createQueryBuilder()
          ->select('*')
          ->from('tl_user')
          ->where('username =:username')
          ->setParameter('username', $userinfo->email)
          ->executeQuery()->fetchAllAssociative();

        $alphabet = "abcdefghijklmnopqrstuwxyzABCDEFGHIJKLMNOPQRSTUWXYZ0123456789";
        $password = "";
        for ($i = 0; $i < 8; $i++) {
            $n = rand(0, strlen($alphabet) - 1);
            $password .= $alphabet[$n];
        }
        $passwordLength = 8;
        if (strlen($password) < $passwordLength) {
            throw new Exception(
              sprintf('The password must be at least %s characters long.', $passwordLength)
            );
        }
        $hash = password_hash($password, PASSWORD_DEFAULT);

        if ($userInDb == null) {
            $logger->log(
              LogLevel::INFO,
              'User "'. $userinfo->email. '" was not found in the database',
              ['contao' => new ContaoContext(__METHOD__, 'ACCESS')]
            );
            $databaseConnection->createQueryBuilder()
              ->insert("tl_user")
              ->values([
                  "tstamp" => "?",
                  "password" => "?",
                  "name" => "?",
                  "language" => "?",
                  "email" => "?",
                  "username" => "?"
              ])->setParameters([
                  0 => time(),
                  1 => $hash,
                  2 => $userinfo->name,
                  3 => $userinfo->getLocale(),
                  4 => $userinfo->email,
                  5 => $userinfo->email
              ])->executeStatement();
        } else {
            $databaseConnection->createQueryBuilder()
              ->update("tl_user")
              ->set("password", ":password")
              ->set("name", ":name")
              ->set("language", ":language")
              ->set("email", ":email")
              ->where("username =:username")
              ->setParameter("password", $hash)
              ->setParameter("name", $userinfo->name)
              ->setParameter("language", $userinfo->getLocale())
              ->setParameter("email", $userinfo->email)
              ->setParameter("username", $userinfo->email)
              ->executeStatement();
        }


        $session = $requestStack->getCurrentRequest()->getSession();
        $userProvider = new ContaoUserProvider($framework, $session, BackendUser::class);

        try {
            $user = $userProvider->loadUserByIdentifier($userinfo->email);
        } catch (UsernameNotFoundException $exception) {
            throw new Exception(
              sprintf('The username "%s" does not exist.', $userinfo->email)
            );
        }

        $response_token = new UsernamePasswordToken($user, null, "contao_backend", $user->getRoles());
        $tokenStorage->setToken($response_token);

        $session->set('_security_'. "contao_backend", serialize($response_token));
        $session->save();

        $event = new InteractiveLoginEvent($requestStack->getCurrentRequest(), $response_token);
        $dispatcher->dispatch($event, 'security.interactive_login');

        $logger->log(
          LogLevel::INFO,
          'User "' . $userinfo->email . '" was logged in automatically',
          ['contao' => new ContaoContext(__METHOD__, 'ACCESS')]
        );

        return $this->redirect($this->generateUrl('contao_backend'));
    }
}
