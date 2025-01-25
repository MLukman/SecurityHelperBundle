<?php

namespace MLukman\SecurityHelperBundle\Authentication;

use DateTime;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Session\FlashBagAwareSessionInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;

trait AddAuthenticationEventsToFlashBagTrait
{
    public static $MESSAGE_WELCOME = 'Welcome, %s.';
    public static $MESSAGE_WELCOME_BACK = 'Welcome back, %s. Your last login was on %s.';

    public function onAuthenticationSuccess(Request $request, UserEntity $user, ?DateTime $previousLogin): void
    {
        $name = ($user->getFullname() ?: $user->getEmail());
        // update last login
        if ($previousLogin) {
            $welcome = sprintf(static::$MESSAGE_WELCOME_BACK, $name, $previousLogin->format('Y-m-d h:i A'));
        } else {
            $welcome = sprintf(static::$MESSAGE_WELCOME, $name);
        }

        $session = $request->getSession();
        if ($session instanceof FlashBagAwareSessionInterface) {
            $session->getFlashBag()->clear();
            $session->getFlashBag()->add('info', $welcome);
        }
    }

    public function onAuthenticationFailure(Request $request, AuthenticatorInterface $authenticator, AuthenticationException $exception): void
    {
        $session = $request->getSession();
        if ($session instanceof FlashBagAwareSessionInterface) {
            $session->getFlashBag()->add('warning', strtr($exception->getMessageKey(), $exception->getMessageData()));
        }
    }
}
