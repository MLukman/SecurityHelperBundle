<?php

namespace MLukman\SecurityHelperBundle\Util;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\Cookie;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

class Redirector implements EventSubscriberInterface
{
    public const COOKIEKEY = 'REDIRECT_URL';

    private ?string $redirectUrl = null;
    private bool $refreshCookie = false;

    public function __construct(private RequestStack $requestStack, private UrlGeneratorInterface $urlGenerator)
    {

    }

    public static function getSubscribedEvents()
    {
        return [
            RequestEvent::class => 'onRequestEvent',
            ResponseEvent::class => 'onResponseEvent',
        ];
    }

    public function onRequestEvent(RequestEvent $event): void
    {
        if ($event->getRequest()->cookies->has(self::COOKIEKEY)) {
            $this->redirectUrl = $event->getRequest()->cookies->get(self::COOKIEKEY);
        }
    }

    public function onResponseEvent(ResponseEvent $event): void
    {
        if ($this->refreshCookie) {
            if ($this->redirectUrl) {
                $event->getResponse()->headers->setCookie(new Cookie(self::COOKIEKEY, $this->redirectUrl));
            } else {
                $event->getResponse()->headers->clearCookie(self::COOKIEKEY);
            }
        }
    }

    protected function storeRedirectUrl(?string $url, bool $overwrite)
    {
        if (!$overwrite && !empty($this->fetchRedirectUrl(false))) {
            return;
        }
        if ($url == $this->loginFullUrl()) {
            return;
        }
        if ($url) {
            $this->redirectUrl = $url;
            $this->refreshCookie = true;
        } else {
            $this->redirectUrl = null;
            $this->refreshCookie = true;
        }
    }

    public function fetchRedirectUrl(bool $clear = true): ?string
    {
        $url = $this->redirectUrl;
        if ($this->request()->cookies->has(self::COOKIEKEY)) {
            $url = $this->request()->cookies->get(self::COOKIEKEY);
        }
        if (!$url &&
            ($referer = $this->request()->headers->get('referer')) &&
            $referer != $this->loginFullUrl() &&
            str_starts_with($referer, $this->request()->getSchemeAndHttpHost())
        ) {
            return $referer;
        }
        if ($clear) {
            $this->redirectUrl = null;
            $this->refreshCookie = true;
        }
        return $url;
    }

    public function saveCurrentRequestUrl(bool $overwrite = true)
    {
        $this->storeRedirectUrl($this->request()->getSchemeAndHttpHost() . $this->request()->getRequestUri(), $overwrite);
    }

    public function saveRefererUrl(bool $overwrite = true)
    {
        $this->storeRedirectUrl($this->request()->headers->get('referer'), $overwrite);
    }

    public function generateRedirectResponse(): ?RedirectResponse
    {
        return ($url = $this->fetchRedirectUrl()) ?
            new RedirectResponse($url, RedirectResponse::HTTP_SEE_OTHER) : null;
    }

    private function loginFullUrl(): string
    {
        return $this->urlGenerator->generate('security_login', referenceType: UrlGeneratorInterface::ABSOLUTE_URL);
    }

    private function request(): Request
    {
        return $this->requestStack->getCurrentRequest();
    }
}
