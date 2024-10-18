<?php

namespace MLukman\SecurityHelperBundle\Authentication;

use DateTime;
use DateTimeInterface;
use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;
use Symfony\Component\Security\Core\User\EquatableInterface;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Validator\Constraints as Assert;
use Symfony\Component\Validator\Context\ExecutionContextInterface;

#[ORM\MappedSuperclass]
#[ORM\HasLifecycleCallbacks]
#[UniqueEntity(
    fields: ['username'],
    errorPath: 'username',
    message: 'This username is already used'
)]
#[UniqueEntity(
    fields: ['method', 'email'],
    errorPath: 'email',
    message: 'This email is already registered'
)]
abstract class UserEntity implements UserInterface, PasswordAuthenticatedUserInterface, EquatableInterface
{
    #[ORM\Column(length: 255)]
    #[Assert\NotBlank(groups: ['registration'])]
    protected ?string $username = null;

    #[ORM\Column(length: 255)]
    #[Assert\NotBlank(groups: ['registration'])]
    protected ?string $method = null;

    #[ORM\Column(length: 255)]
    protected ?string $credential = null;

    #[ORM\Column(length: 255)]
    #[Assert\NotBlank(groups: ['registration'])]
    #[Assert\Email(groups: ['registration'])]
    protected ?string $email = null;

    #[ORM\Column(length: 255, nullable: true)]
    protected ?string $authSession = null;

    #[ORM\Column(type: Types::DATETIME_MUTABLE, nullable: true)]
    protected ?DateTimeInterface $lastLogin = null;

    #[ORM\Column(type: Types::DATETIME_MUTABLE, nullable: true, options: ["default" => "CURRENT_TIMESTAMP"])]
    protected ?DateTimeInterface $registered;

    #[ORM\Column(length: 255, nullable: true)]
    #[Assert\NotBlank(groups: ['profile'])]
    protected ?string $fullname = null;

    #[ORM\Column(length: 8, nullable: true)]
    #[Assert\NotBlank(groups: ['profile'])]
    protected ?string $language = null;

    #[ORM\Column(length: 50, nullable: true)]
    #[Assert\NotBlank(groups: ['profile'])]
    protected ?string $timezone = null;

    #[ORM\Column(nullable: true)]
    protected ?bool $blocked = null;

    #[ORM\Column(length: 255, nullable: true)]
    protected ?string $blockedReason = null;

    #[ORM\Column(length: 64, nullable: true)]
    protected ?string $resetCode = null;

    #[ORM\Column(nullable: true)]
    protected array $attributes = [];

    public function __construct(
        string $method,
        string $credential,
        ?string $username = null
    ) {
        $this->username = $username ?: sprintf("%s-%s", $method, $credential);
        $this->method = $method;
        $this->credential = $credential;
        $this->registered = new DateTime();
    }

    #[Assert\Callback]
    public function validate(ExecutionContextInterface $context, $payload)
    {
        if (empty($this->getEmail()) && $this->getMethod() != 'password') {
            $provider = ucwords($this->getMethod());
            $context->buildViolation("Your email address is missing from your {$provider} profile. Please update your email address there before retrying to sign in here.")
                ->atPath('email')
                ->addViolation();
        }
    }

    public function getUsername(): ?string
    {
        return $this->username;
    }

    public function getMethod(): ?string
    {
        return $this->method;
    }

    public function getCredential(): ?string
    {
        return $this->credential;
    }

    public function getAuthSession(): ?string
    {
        return $this->authSession;
    }

    public function setAuthSession(?string $authSession): void
    {
        $this->authSession = $authSession;
    }

    abstract public function getRoles(): array;

    abstract public function setRoles(array $roles): self;

    public function hasRole(string $role): bool
    {
        return in_array($role, $this->getRoles());
    }

    public function addRole(string $role): array
    {
        $this->setRoles(array_merge([$role], $this->getRoles()));
        return $this->getRoles();
    }

    public function removeRole(string $role): array
    {
        $this->setRoles(array_values(
            array_filter(
                $this->getRoles(),
                function ($r) use ($role) {
                    return $r != $role;
                }
            )
        ));
        return $this->getRoles();
    }

    public function getLastLogin(): ?DateTimeInterface
    {
        return $this->lastLogin;
    }

    public function setLastLogin(DateTimeInterface $lastLogin): self
    {
        $this->lastLogin = $lastLogin;

        return $this;
    }

    public function getRegistered(): ?DateTimeInterface
    {
        return $this->registered;
    }

    public function getUserIdentifier(): string
    {
        return $this->getUsername();
    }

    public function getFullname(): ?string
    {
        return $this->fullname;
    }

    public function setFullname(?string $fullname): self
    {
        $this->fullname = $fullname;

        return $this;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(string $email): self
    {
        $this->email = $email;

        return $this;
    }

    public function getLanguage(): ?string
    {
        return $this->language;
    }

    public function setLanguage(?string $language): self
    {
        $this->language = $language;

        return $this;
    }

    public function getTimezone(): ?string
    {
        return $this->timezone;
    }

    public function setTimezone(?string $timezone): self
    {
        $this->timezone = $timezone;

        return $this;
    }

    public function isBlocked(): ?bool
    {
        return !empty($this->blockedReason) || $this->blocked;
    }

    public function setBlocked(?bool $blocked): self
    {
        $this->blocked = $blocked;
        $this->blockedReason = $blocked ? 'Unknown reason' : null;
    }

    public function getBlockedReason(): ?string
    {
        return $this->blockedReason;
    }

    public function setBlockedReason(?string $blockedReason): self
    {
        $this->blockedReason = $blockedReason;

        return $this;
    }

    public function getResetCode(): ?string
    {
        return $this->resetCode;
    }

    public function setResetCode(?string $resetCode): self
    {
        $this->resetCode = $resetCode;

        return $this;
    }

    public function getAttributes(): array
    {
        return $this->attributes;
    }

    public function setAttributes(?array $attributes): self
    {
        $this->attributes = $attributes;

        return $this;
    }

    public function getPassword(): ?string
    {
        return $this->credential;
    }

    public function setPassword(?string $password): self
    {
        $this->credential = $password;

        return $this;
    }

    public function isEqualTo(UserInterface $user): bool
    {
        return $user instanceof self &&
            $user->getUserIdentifier() == $this->getUserIdentifier() &&
            $user->getRoles() == $this->getRoles() &&
            $user->getAuthSession() == $this->getAuthSession();
    }

    public function eraseCredentials(): void
    {

    }

    public function displayTitle(): string
    {
        return $this->fullname;
    }

    public function merge(UserEntity $tobemerged)
    {

    }
}
