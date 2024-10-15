<?php

namespace MLukman\SecurityHelperBundle\Command;

use MLukman\SecurityHelperBundle\Authentication\AuthenticationRepositoryInterface;
use MLukman\SecurityHelperBundle\Authentication\UserEntity;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Contracts\Service\Attribute\Required;

#[AsCommand(
    name: 'security:user:list',
    description: 'List all users',
)]
class UserListCommand extends Command
{
    protected ?AuthenticationRepositoryInterface $authRepository;

    #[Required]
    public function required(?AuthenticationRepositoryInterface $authRepository)
    {
        $this->authRepository = $authRepository;
    }

    protected function configure(): void
    {

    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);

        $users = $this->authRepository->queryAllUserEntities(0, PHP_INT_MAX);
        $rows = [];
        foreach ($users as $user) {
            /* @var $user UserEntity */
            $rows[] = [
                $user->getUsername(),
                $user->getMethod(),
                $user->getEmail(),
                implode(", ", $user->getRoles()),
                $user->getBlockedReason() ?: '-',
            ];
        }
        $table = new Table($output);
        $table
            ->setHeaders(['Username', 'Method', 'Email', 'Roles', 'Block Reason'])
            ->setRows($rows)
        ;
        $table->render();
        return Command::SUCCESS;
    }
}
