<?php

namespace MLukman\SecurityHelperBundle\Authentication;

use Doctrine\ORM\EntityRepository;

interface AuthenticationRepositoryInterface
{
    public function getDefaultRedirectRoute(): string;

    public function newUserEntity(string $method, string $credential, string $username = null): UserEntity;

    public function getUserEntityRepository(): EntityRepository;
    
    public function generateAuthSession(UserEntity $user): string;

    public function saveUserEntity(UserEntity $user): void;

    public function deleteUserEntity(UserEntity $user): void;

    public function sendResetPasswordEmail(UserEntity $user): void;

    public function countAllUserEntities(): int;

    public function queryAllUserEntities(int $start, int $rows): array;
}
