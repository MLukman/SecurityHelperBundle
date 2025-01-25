<?php

namespace MLukman\SecurityHelperBundle\Util;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\Event\ResponseEvent;

class CookieInjector implements EventSubscriberInterface
{
    protected array $cookies = [];

    public function __construct(protected RequestStack $requestStack)
    {

    }

    public static function getSubscribedEvents(): array
    {
        return [
            ResponseEvent::class => 'onResponseEvent',
        ];
    }

    public function hasCookie(string $key): bool
    {
        return isset($this->cookies[$key]) || $this->requestStack->getMainRequest()->cookies->has($key);
    }

    public function getCookie(string $key, bool $remove = false): ?string
    {
        $cookie = $this->cookies[$key] ?? $this->requestStack->getMainRequest()->cookies->get($key);
        if ($remove) {
            $this->cookies[$key] = null;
        }
        return $cookie;
    }

    public function setCookie(string $key, ?string $value): void
    {
        $this->cookies[$key] = $value;
    }

    public function removeCookie(string $key): void
    {
        $this->cookies[$key] = null;
    }

    public function onResponseEvent(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }
        $headers = $event->getResponse()->headers;
        foreach ($this->cookies as $key => $value) {
            if (is_null($value)) {
                $headers->clearCookie($key);
            } else {
                $headers->setCookie(Cookie::create($key, $value));
            }
        }
    }
}
