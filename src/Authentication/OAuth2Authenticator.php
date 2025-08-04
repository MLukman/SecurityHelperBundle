<?php

namespace MLukman\SecurityHelperBundle\Authentication;

use Exception;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Security\Authenticator\OAuth2Authenticator as KnpUOAuth2Authenticator;
use KnpU\OAuth2ClientBundle\Security\Exception\IdentityProviderAuthenticationException;
use League\OAuth2\Client\Provider\ResourceOwnerInterface;
use MLukman\DoctrineHelperBundle\Service\ObjectValidator;
use MLukman\SecurityHelperBundle\Util\CookieInjector;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\DependencyInjection\Attribute\AutowireIterator;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
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

    use TargetPathTrait;

    public const OAUTH_REDIRECT_ROUTE = 'security_oauth2_connect_check';

    public function __construct(
        private AuthenticationListener $authListener,
        protected ClientRegistry $clientRegistry,
        protected ObjectValidator $validator,
        protected Security $security,
        protected CookieInjector $cookies,
        #[AutowireIterator('oauth2.authenticator.visitor')] protected iterable $visitors
    ) {
        
    }

    public function supports(Request $request): ?bool
    {
        // continue ONLY if the current ROUTE matches the check ROUTE
        return $request->attributes->get('_route') === self::OAUTH_REDIRECT_ROUTE && $this->authListener->isEnabled();
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
        if ($this->cookies->getCookie('sf_security_remember')) {
            $rememberMe->enable();
            $this->cookies->removeCookie('sf_security_remember');
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
            $user = $this->authListener->repo()->newUserEntity($clientId, $uid);

            // let visitors populate it
            foreach ($this->visitors as $visitor) {
                $visitor->prepareNewUserFromResourceOwner($user, $oauth2User);
            }

            // fallback if email is missing
            if (!$user->getEmail()) {
                $user->setEmail($user->getUserIdentifier());
            }
        }

        if (($errors = $this->validator->validate($user))) {
            $errorMessages = [];
            foreach ($errors as $f => $errorArray) {
                foreach ($errorArray as $error) {
                    $errorMessages[] = "$f: $error";
                }
            }
            throw new Exception(join(' ', $errorMessages));
        }
        $this->authListener->repo()->saveUserEntity($user);

        return $user;
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return null;
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        return $this->authListener->handleAuthenticationFailure($request, $this, $exception);
    }
}
