<?php

namespace MLukman\SecurityHelperBundle\Authentication;

use Symfony\Component\Security\Core\User\UserInterface;

interface AuthenticationRepositoryInterface
{

    public function getDefaultRedirectRoute(): string;

    public function newUserEntity(string $method, string $credential, string $username = null): UserEntity;

    public function queryUserEntity(string $method, string $criteriaField, string $criteriaValue): ?UserEntity;

    public function queryUserEntityFromSecurityUser(UserInterface $securityUser): ?UserEntity;

    public function saveUserEntity(UserEntity $user): void;

    public function sendResetPasswordEmail(UserEntity $user): void;
}
