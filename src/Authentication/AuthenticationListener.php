<?php

namespace MLukman\SecurityHelperBundle\Authentication;

use DateTime;
use MLukman\SecurityHelperBundle\Util\ReCaptchaUtil;
use MLukman\SecurityHelperBundle\Util\Redirector;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\DependencyInjection\Attribute\AutowireIterator;
use Symfony\Component\DependencyInjection\Exception\AutowiringFailedException;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ControllerEvent;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\Exception\CustomUserMessageAuthenticationException;
use Symfony\Component\Security\Core\Exception\InvalidCsrfTokenException;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Security\Csrf\CsrfToken;
use Symfony\Component\Security\Csrf\CsrfTokenManagerInterface;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;
use Symfony\Component\Security\Http\Event\LoginSuccessEvent;
use Symfony\Component\Security\Http\Event\LogoutEvent;
use Symfony\Contracts\Service\Attribute\Required;

class AuthenticationListener implements AuthenticationEntryPointInterface, EventSubscriberInterface
{
    protected Security $security;
    protected UrlGeneratorInterface $urlGenerator;
    protected CsrfTokenManagerInterface $csrfTokenManager;
    protected Redirector $redirector;
    protected ReCaptchaUtil $recaptcha;
    protected ?AuthenticationRepositoryInterface $authRepository;
    protected iterable $auditLoggers;
    protected ?UserInterface $currentUser;

    #[Required]
    public function requiredByAAL(
        Security $security,
        UrlGeneratorInterface $urlGenerator,
        CsrfTokenManagerInterface $csrfTokenManager,
        Redirector $redirector,
        ReCaptchaUtil $recaptcha,
        ?AuthenticationRepositoryInterface $authRepository,
        #[AutowireIterator('security.audit.logger')] iterable $auditLoggers
    ) {
        $this->security = $security;
        $this->urlGenerator = $urlGenerator;
        $this->csrfTokenManager = $csrfTokenManager;
        $this->redirector = $redirector;
        $this->recaptcha = $recaptcha;
        $this->authRepository = $authRepository;
        $this->auditLoggers = $auditLoggers;
    }

    public function repo(): AuthenticationRepositoryInterface
    {
        if (!$this->authRepository) {
            throw new AutowiringFailedException(AuthenticationRepositoryInterface::class, self::class . ' requires ' . AuthenticationRepositoryInterface::class . ' to be implemented and aliased by the application.');
        }
        return $this->authRepository;
    }

    public function getSecurity(): Security
    {
        return $this->security;
    }

    public function log(UserEntity $user, string $event, array $details = []): void
    {
        foreach ($this->auditLoggers as $auditLogger) {
            $auditLogger->logAuthentication($user, $event, $details);
        }
    }

    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        $this->redirector->saveCurrentRequestUrl();
        return new RedirectResponse($this->urlGenerator->generate($this->getLoginRoute()));
    }

    public function isEnabled(): bool
    {
        return !empty($this->authRepository);
    }

    public static function getSubscribedEvents(): array
    {
        return [
            LoginSuccessEvent::class => ['onLogin', -999],
            LogoutEvent::class => ['onLogout', -999],
            ControllerEvent::class => ['onController', -999],
        ];
    }

    public function loginFormPreAuthenticationChecks(Request $request): void
    {
        $csrf = $request->request->get('csrf_token');

        // check CSRF
        if (!$this->csrfTokenManager->isTokenValid(new CsrfToken('authenticate', $csrf))) {
            throw new InvalidCsrfTokenException('Invalid CSRF');
        }

        // check recaptcha
        if ($this->recaptcha->isEnabled()) {
            $resp = $this->recaptcha->verify($request->request->get('g-recaptcha-response'));
            if (!$resp->isSuccess()) {
                throw new CustomUserMessageAuthenticationException('reCAPTCHA error: ' . join(", ", $resp->getErrorCodes()));
            }
        }
    }

    public function onController(ControllerEvent $event): void
    {
        // store the page URL that redirect to login page in order to redirect back after login
        if ('security_login' == $event->getRequest()->attributes->get('_route')) {
            $this->redirector->saveRefererUrl();
        }
    }

    public function onLogin(LoginSuccessEvent $event): void
    {
        $user = ($securityUser = $this->security->getUser()) ?
            $this->queryUserEntityFromSecurityUser($securityUser) : null;

        if ($user) {
            $lastlogin = $user->getLastLogin();
            $this->log($user, 'LOGIN');
            $user->setLastLogin(new DateTime());
            $user->setAuthSession($this->repo()->generateAuthSession($user));

            // read user's language
            if ($user && ($userLanguage = $user->getLanguage())) {
                $event->getRequest()->getSession()->set('_locale', $userLanguage);
            }

            $this->repo()->saveUserEntity($user);
            $this->repo()->onAuthenticationSuccess($event->getRequest(), $user, $lastlogin);
        }

        // redirect
        if (($redirect = $this->redirector->generateRedirectResponse())) {
            $event->setResponse($redirect);
        } else {
            $response = new RedirectResponse(
                $this->urlGenerator->generate($this->getDefaultRedirectRoute()),
                RedirectResponse::HTTP_SEE_OTHER
            );
            $event->setResponse($response);
        }
    }

    public function onLogout(LogoutEvent $event): void
    {
        if ($event->getToken()) {
            $this->log($event->getToken()->getUser(), 'LOGOUT');
        }
        // redirect to redirect_uri query parameter or default redirect route
        $redirect_uri = $event->getRequest()->query->get('redirect_uri') ?: $this->urlGenerator->generate($this->getDefaultRedirectRoute());
        $response = new RedirectResponse(
            $redirect_uri,
            RedirectResponse::HTTP_SEE_OTHER
        );
        $event->setResponse($response);
    }

    public function getDefaultRedirectRoute(): string
    {
        return $this->repo()->getDefaultRedirectRoute();
    }

    public function getLoginRoute(): string
    {
        return 'security_login';
    }

    public function getLogoutRoute(): string
    {
        return 'security_logout';
    }

    public function currentUser(): ?UserEntity
    {
        if (!isset($this->currentUser)) {
            $this->currentUser = ($securityUser = $this->security->getUser()) ?
                $this->queryUserEntityFromSecurityUser($securityUser) : null;
        }
        return $this->currentUser;
    }

    public function newUserEntity(string $method, string $credential, string $username = null): UserEntity
    {
        return $this->repo()->newUserEntity($method, $credential, $username);
    }

    public function queryUserEntity(string $method, string $criteriaField, string $criteriaValue, bool $ignoreBlocked = false): ?UserEntity
    {
        $user = $this->repo()->getUserEntityRepository()->findOneBy([
            'method' => $method,
            $criteriaField => $criteriaValue,
        ]);
        if ($user && ($block = $user->getBlockedReason()) && !$ignoreBlocked) { // User blocked
            throw new CustomUserMessageAuthenticationException(sprintf('Sorry but you have been blocked from logging in with the following reason: %s. Please contact an administrator if you think it is a mistake.', $block));
        }

        return $user;
    }

    public function queryUserEntityFromSecurityUser(UserInterface $securityUser): ?UserEntity
    {
        return $this->repo()->getUserEntityRepository()->findOneBy(['username' => $securityUser->getUserIdentifier()]);
    }

    public function saveUserEntity(UserEntity &$user): void
    {
        $this->repo()->saveUserEntity($user);
    }

    public function handleAuthenticationFailure(Request $request, AuthenticatorInterface $authenticator, AuthenticationException $exception): ?Response
    {
        $this->repo()->onAuthenticationFailure($request, $authenticator, $exception);
        return new RedirectResponse($this->urlGenerator->generate($this->getLoginRoute()));
    }
}
