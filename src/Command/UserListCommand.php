<?php

namespace MLukman\SecurityHelperBundle\Command;

use DateTime;
use MLukman\SecurityHelperBundle\Authentication\AuthenticationRepositoryInterface;
use MLukman\SecurityHelperBundle\Authentication\UserEntity;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Helper\Table;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Console\Style\SymfonyStyle;
use Symfony\Component\PropertyAccess\PropertyAccess;
use Symfony\Contracts\Service\Attribute\Required;

#[AsCommand(
    name: 'security:user:list',
    description: 'List all users',
)]
class UserListCommand extends Command
{
    protected ?AuthenticationRepositoryInterface $authRepository;
    protected $columns = [
        'Username' => 'username',
        'Method' => 'method',
        'Email' => 'email',
        'Roles' => 'roles',
        'Registered' => 'registered',
        'Last Login' => 'lastLogin',
        'Blocked Reason' => 'blockedReason',
    ];

    #[Required]
    public function required(?AuthenticationRepositoryInterface $authRepository)
    {
        $this->authRepository = $authRepository;
    }

    public function addColumns(array $columns): void
    {
        $this->columns = array_merge($this->columns, $columns);
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $io = new SymfonyStyle($input, $output);
        $pa = PropertyAccess::createPropertyAccessor();
        $users = $this->authRepository->queryAllUserEntities(0, PHP_INT_MAX);
        $rows = [];
        $this->columns = array_filter($this->columns);
        foreach ($users as $user) {
            /* @var $user UserEntity */
            $row = [];
            foreach ($this->columns as $field) {
                $value = $user;
                foreach (explode('.', $field) as $token) {
                    $value = $pa->getValue($value, $token);
                    if (is_null($value)) {
                        break;
                    }
                }
                if (is_array($value)) {
                    $value = implode(", ", $value);
                }
                if ($value instanceof DateTime) {
                    $value = $value->format('Y-m-d');
                }
                $row[] = (string) $value ?: '-';
            }
            $rows[] = $row;
        }
        $table = new Table($output);
        $table
            ->setHeaders(array_keys($this->columns))
            ->setRows($rows)
        ;
        $table->render();
        return Command::SUCCESS;
    }
}
