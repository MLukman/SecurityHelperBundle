<?php

namespace MLukman\SecurityHelperBundle\Command;

use MLukman\SecurityHelperBundle\Authentication\AuthenticationRepositoryInterface;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\DependencyInjection\Attribute\AutowireIterator;
use Symfony\Contracts\Service\Attribute\Required;

#[AsCommand(
    name: 'security:user:roles',
    description: 'Modify roles of a user',
)]
class UserRolesCommand extends Command
{
    protected ?AuthenticationRepositoryInterface $authRepository;
    protected iterable $auditLoggers;

    #[Required]
    public function required(
        ?AuthenticationRepositoryInterface $authRepository,
        #[AutowireIterator('security.audit.logger')] iterable $auditLoggers
    ) {
        $this->authRepository = $authRepository;
        $this->auditLoggers = $auditLoggers;
    }

    protected function configure(): void
    {
        $this
            ->addArgument('username', InputArgument::REQUIRED, 'The username to modify')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $username = $input->getArgument('username');

        $user = $this->authRepository->queryUserEntityByUsername($username);
        if (!$user) {
            $io->error(sprintf("User with username '%s' is not found", $username));
            return Command::FAILURE;
        }
        $roles = $user->getRoles();

        while (($role = strtoupper($io->ask(sprintf("Current roles are %s. Please enter a new role to add, or an existing role to remove. Enter none to save and exit", \json_encode($roles)))))) {
            if (in_array($role, $roles)) {
                $user->removeRole($role);
            } elseif (str_starts_with($role, 'ROLE_')) {
                $user->addRole($role);
            } else {
                $io->warning('Role must start with "ROLE_"');
                $role = null;
            }
            if ($role && $roles == $user->getRoles()) {
                $io->warning(sprintf('For some reason, your application logic resisted the addition/removal of the role. Please check the logic inside "setRoles()" method of the class %s.', get_class($user)));
            } else {
                $roles = $user->getRoles();
            }
        }

        $this->authRepository->saveUserEntity($user);
        $io->success(sprintf("Roles of user '%s' has been successfully saved.", $username));

        return Command::SUCCESS;
    }
}
