<?php

namespace MLukman\SecurityHelperBundle\Authentication;

use DateTime;
use Exception;
use MLukman\SecurityHelperBundle\Util\ReCaptchaUtil;
use MLukman\SecurityHelperBundle\Util\Redirector;
use Symfony\Bundle\SecurityBundle\Security;
use Symfony\Component\DependencyInjection\Attribute\TaggedIterator;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Session\FlashBagAwareSessionInterface;
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

    public const MESSAGE_WELCOME = 'Welcome, %s.';
    public const MESSAGE_WELCOME_BACK = 'Welcome back, %s. Your last login was on %s.';

    protected Security $security;
    protected UrlGeneratorInterface $urlGenerator;
    protected CsrfTokenManagerInterface $csrfTokenManager;
    protected Redirector $redirector;
    protected ReCaptchaUtil $recaptcha;
    protected ?AuthenticationRepositoryInterface $authRepository;
    protected iterable $auditLoggers;

    #[Required]
    public function requiredByAAL(Security $security,
            UrlGeneratorInterface $urlGenerator,
            CsrfTokenManagerInterface $csrfTokenManager,
            Redirector $redirector,
            ReCaptchaUtil $recaptcha,
            ?AuthenticationRepositoryInterface $authRepository,
            #[TaggedIterator('security.audit.logger')] iterable $auditLoggers)
    {
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
            throw new Exception('Implementation Error: application is required to implement and alias the interface ' . AuthenticationRepositoryInterface::class);
        }
        return $this->authRepository;
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
            LoginSuccessEvent::class => 'onLogin',
            LogoutEvent::class => 'onLogout',
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

    public function onLogin(LoginSuccessEvent $event): void
    {
        $user = ($securityUser = $this->security->getUser()) ?
                $this->queryUserEntityFromSecurityUser($securityUser) : null;

        if ($user) {


            $name = ($user->getFullname() ?: $user->getEmail());
            // update last login
            if (($lastlogin = $user->getLastLogin())) {
                $welcome = sprintf(self::MESSAGE_WELCOME_BACK, $name, $lastlogin->format('Y-m-d h:i A'));
            } else {
                $welcome = sprintf(self::MESSAGE_WELCOME, $name);
            }

            $session = $event->getRequest()->getSession();
            if ($session instanceof FlashBagAwareSessionInterface) {
                $session->getFlashBag()->clear();
                $session->getFlashBag()->add('info', $welcome);
                $this->log($user, 'LOGIN');
            }
            $user->setLastLogin(new DateTime());

            // read user's language
            if ($user && ($userLanguage = $user->getLanguage())) {
                $session->set('_locale', $userLanguage);
            }

            $this->saveUserEntity($user);
        }

        // redirect
        if (($redirect = $this->redirector->generateRedirectResponse())) {
            $event->setResponse($redirect);
        }
    }

    public function onLogout(LogoutEvent $event): void
    {
        if ($event->getToken()) {
            $this->log($event->getToken()->getUser(), 'LOGOUT');
        }
        // redirect if there is redirect_uri query parameter
        $request = $event->getRequest();
        if (($redirect_uri = $request->query->get('redirect_uri'))) {
            $response = new RedirectResponse(
                    $redirect_uri, RedirectResponse::HTTP_SEE_OTHER
            );
            $event->setResponse($response);
        } else {
            $response = new RedirectResponse(
                    $this->urlGenerator->generate($this->getDefaultRedirectRoute()),
                    RedirectResponse::HTTP_SEE_OTHER);
            $event->setResponse($response);
        }
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

    public function newUserEntity(string $method, string $credential, string $username = null): UserEntity
    {
        return $this->repo()->newUserEntity($method, $credential, $username);
    }

    public function queryUserEntity(string $method, string $criteriaField, string $criteriaValue, bool $ignoreBlocked = false): ?UserEntity
    {
        $user = $this->repo()->queryUserEntity($method, $criteriaField, $criteriaValue);
        if ($user && $user->isBlocked() && !$ignoreBlocked) { // User blocked
            throw new CustomUserMessageAuthenticationException('Sorry but you have been blocked from logging in. Please contact an administrator if you think it is a mistake.');
        }

        return $user;
    }

    public function currentUser(): ?UserEntity
    {
        return ($securityUser = $this->security->getUser()) ?
                $this->queryUserEntityFromSecurityUser($this->security->getUser()) : null;
    }

    public function queryUserEntityFromSecurityUser(UserInterface $securityUser): ?UserEntity
    {
        return $this->repo()->queryUserEntityFromSecurityUser($securityUser);
    }

    public function saveUserEntity(UserEntity $user): void
    {
        $this->repo()->saveUserEntity($user);
    }

    public function handleAuthenticationFailure(Request $request, AuthenticatorInterface $authenticator, AuthenticationException $exception): ?Response
    {
        $session = $request->getSession();
        if ($session instanceof FlashBagAwareSessionInterface) {
            $session->getFlashBag()->add('warning', strtr($exception->getMessageKey(), $exception->getMessageData()));
        }
        return new RedirectResponse($this->urlGenerator->generate($this->getLoginRoute()));
    }
}