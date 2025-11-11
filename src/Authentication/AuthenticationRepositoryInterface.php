<?php

namespace MLukman\SecurityHelperBundle\Authentication;

use DateTime;
use Doctrine\ORM\EntityRepository;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\AuthenticatorInterface;

interface AuthenticationRepositoryInterface
{
    /**
     * Return the route name to redirect to after login if there is no redirect url stored before the login process start
     * @return string The route name
     */
    public function getDefaultRedirectRoute(): string;

    /**
     * Create
     * @param string $method
     * @param string $credential
     * @param string $username
     * @return UserEntity
     */
    public function newUserEntity(string $method, string $credential, ?string $username = null): UserEntity;

    public function getUserEntityRepository(): EntityRepository;

    public function generateAuthSession(UserEntity $user): string;

    public function saveUserEntity(UserEntity &$user): void;

    public function deleteUserEntity(UserEntity $user): void;

    public function sendResetPasswordEmail(UserEntity $user): void;

    public function countAllUserEntities(): int;

    public function queryAllUserEntities(int $start, int $rows): array;

    public function onAuthenticationSuccess(Request $request, UserEntity $user, ?DateTime $previousLogin): void;

    public function onAuthenticationFailure(Request $request, AuthenticatorInterface $authenticator, AuthenticationException $exception): void;
}
