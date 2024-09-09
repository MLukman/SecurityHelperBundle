<?php

namespace MLukman\SecurityHelperBundle\Authentication;

use Doctrine\ORM\EntityManagerInterface;
use Exception;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Security\Authenticator\OAuth2Authenticator as KnpUOAuth2Authenticator;
use KnpU\OAuth2ClientBundle\Security\Exception\IdentityProviderAuthenticationException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use MLukman\DoctrineHelperBundle\Service\ObjectValidator;
use MLukman\SecurityHelperBundle\Util\Redirector;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\DependencyInjection\Attribute\TaggedIterator;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Router;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\RememberMeBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\Util\TargetPathTrait;

class OAuth2Authenticator extends KnpUOAuth2Authenticator
{

    const OAUTH_REDIRECT_ROUTE = 'security_oauth2_connect_check';

    use TargetPathTrait;

    public function __construct(private AuthenticationListener $authListener,
            protected ClientRegistry $clientRegistry,
            protected EntityManagerInterface $entityManager,
            protected ObjectValidator $validator,
            protected RouterInterface $router,
            protected Security $security,
            protected RequestStack $requestStack,
            protected Redirector $redirector,
            #[TaggedIterator('oauth2.authenticator.visitor')] protected iterable $visitors)
    {
        
    }

    public function supports(Request $request): ?bool
    {
        // continue ONLY if the current ROUTE matches the check ROUTE
        return $request->attributes->get('_route') === self::OAUTH_REDIRECT_ROUTE && $this->authListener->isEnabled();
    }

    public function getRedirectionToProvider(string $client, ?string $redirect_after_login = null): ?RedirectResponse
    {
        $request = $this->requestStack->getMainRequest();
        // store remember me flag if any
        if ($request->query->get('_remember_me')) {
            $request->getSession()->set('_remember_me', true);
        }

        // store redirect after login into state
        $redirect = $redirect_after_login ?:
                $request->headers->get('referer') ?:
                $this->router->generate($this->authListener->getDefaultRedirectRoute(), referenceType: Router::ABSOLUTE_URL);
        $options = ['state' => rtrim(strtr(base64_encode($redirect), '+/', '-_'), '=')];

        // prepare redirect to provider
        $clientObj = $this->clientRegistry->getClient($client);
        foreach ($this->visitors as $visitor) {
            $visitor->prepareRedirectOptions($options, $clientObj);
        }
        return $clientObj->redirect([], $options);
    }

    public function authenticate(Request $request): Passport
    {
        $clientId = $request->attributes->get('_route_params')['client'];
        $client = $this->clientRegistry->getClient($clientId);

        try {
            $accessToken = $this->fetchAccessToken($client);
            $oauth2User = $client->fetchUserFromToken($accessToken);
        } catch (IdentityProviderAuthenticationException $e) {
            throw new CustomUserMessageAuthenticationException('Authentication request has expired. Please retry.');
        }

        $authenticatedUser = $this->createOrGetUser($clientId, $oauth2User);
        if (($sessionUser = $this->security->getUser()) &&
                ($existingUser = $this->authListener->queryUserEntityFromSecurityUser($sessionUser)) &&
                $authenticatedUser != $existingUser) {
            $existingUser->merge($authenticatedUser);
        }

        $rememberMe = new RememberMeBadge();
        if ($request->getSession()->get('_remember_me')) {
            $rememberMe->enable();
            $request->getSession()->remove('_remember_me');
        }

        return new SelfValidatingPassport(
                new UserBadge($accessToken->getToken(), fn() => $authenticatedUser),
                [$rememberMe]
        );
    }

    protected function createOrGetUser(string $clientId, ResourceOwnerInterface $oauth2User): UserEntity
    {
        $uid = $oauth2User->getId();

        if (!($user = $this->authListener->queryUserEntity($clientId, 'credential', $uid))) {
            // create new user
            $user = $this->authListener->newUserEntity($clientId, $uid);

            // let visitors populate it
            foreach ($this->visitors as $visitor) {
                $visitor->prepareNewUserFromResourceOwner($user, $oauth2User);
            }

            // fallback if email is missing
            if (!$user->getEmail()) {
                $user->setEmail($user->getUserIdentifier());
            }
        }

        $user->setAuthSession(bin2hex(random_bytes(16)));
        if (($errors = $this->validator->validate($user))) {
            $errorMessages = [];
            foreach ($errors as $f => $errorArray) {
                foreach ($errorArray as $error) {
                    $errorMessages[] = "$f: $error";
                }
            }
            throw new Exception(join(' ', $errorMessages));
        }
        $this->entityManager->persist($user);
        $this->entityManager->flush();

        return $user;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return new RedirectResponse(
                $this->getTargetPath($request->getSession(), $firewallName) ?:
                base64_decode(strtr($request->query->get('state'), '-_', '+/')) ?:
                $this->router->generate($this->authListener->getDefaultRedirectRoute()));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return $this->authListener->handleAuthenticationFailure($request, $this, $exception);
    }
}
