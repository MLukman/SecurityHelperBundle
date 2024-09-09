<?php

namespace MLukman\SecurityHelperBundle\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

interface LoginControllerInterface {

    public function login(Request $request, ClientRegistry $clientRegistry): Response;
}
