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
        name: 'security:user:delete',
        description: 'Delete a user',
    )]
class UserDeleteCommand extends Command
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
            ->addArgument('username', InputArgument::REQUIRED, 'The username to delete')
        ;
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $username = $input->getArgument('username');

        $user = $this->authRepository->getUserEntityRepository()->findOneBy(['username' => $username]);
        if (!$user) {
            $io->error(sprintf("User with username '%s' is not found", $username));
            return Command::FAILURE;
        }
        foreach ($this->auditLoggers as $auditLogger) {
            $auditLogger->logAuthentication($user, SecurityEvent::DELETED, [
                'source' => __CLASS__
            ]);
        }

        $this->authRepository->deleteUserEntity($user);
        $io->success(sprintf("User '%s' has been successfully deleted.", $username));

        return Command::SUCCESS;
    }
}
