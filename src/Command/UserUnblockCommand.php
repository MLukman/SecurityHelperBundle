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
    name: 'security:user:unblock',
    description: 'Unblock a user',
)]
class UserUnblockCommand extends Command
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
            ->addArgument('username', InputArgument::REQUIRED, 'The username to unblock')
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
        if (!$user->getBlockedReason()) {
            $io->error(sprintf("User with username '%s' is not blocked", $username));
            return Command::FAILURE;
        }

        $user->setBlockedReason(null);
        $this->authRepository->saveUserEntity($user);
        foreach ($this->auditLoggers as $auditLogger) {
            $auditLogger->logAuthentication($user, 'UNBLOCKED', [
                'source' => __CLASS__
            ]);
        }

        $io->success(sprintf("User '%s' has been successfully unblocked.", $username));

        return Command::SUCCESS;
    }
}
