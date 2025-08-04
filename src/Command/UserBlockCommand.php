<?php

namespace MLukman\SecurityHelperBundle\Command;

use MLukman\SecurityHelperBundle\Authentication\AuthenticationRepositoryInterface;
use MLukman\SecurityHelperBundle\Util\SecurityEvent;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\DependencyInjection\Attribute\AutowireIterator;
use Symfony\Contracts\Service\Attribute\Required;

#[AsCommand(
        name: 'security:user:block',
        description: 'Block a user',
    )]
class UserBlockCommand extends Command
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
            ->addArgument('username', InputArgument::REQUIRED, 'The username to block')
            ->addArgument('reason', InputArgument::REQUIRED, 'The reason the user is blocked')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $username = $input->getArgument('username');
        $reason = $input->getArgument('reason');

        $user = $this->authRepository->getUserEntityRepository()->findOneBy(['username' => $username]);
        if (!$user) {
            $io->error(sprintf("User with username '%s' is not found", $username));
            return Command::FAILURE;
        }

        $user->setBlockedReason($reason);
        $this->authRepository->saveUserEntity($user);
        foreach ($this->auditLoggers as $auditLogger) {
            $auditLogger->logAuthentication($user, SecurityEvent::BLOCKED, [
                'source' => __CLASS__
            ]);
        }

        $io->success(sprintf("User '%s' has been successfully blocked.", $username));

        return Command::SUCCESS;
    }
}
