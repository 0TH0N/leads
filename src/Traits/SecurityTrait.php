<?php


namespace App\Traits;


use App\Entity\User;
use App\Exception\AppException;
use App\Repository\UserRepository;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;

trait SecurityTrait
{
    /**
     * @var UserPasswordEncoderInterface
     */
    private $passwordEncoder;
    /**
     * @var UserRepository
     */
    private $userRepository;

    /**
     * SecurityTrait constructor.
     *
     * @param UserPasswordEncoderInterface $passwordEncoder
     * @param UserRepository               $userRepository
     */
    public function __construct(UserPasswordEncoderInterface $passwordEncoder, UserRepository $userRepository)
    {

        $this->passwordEncoder = $passwordEncoder;
        $this->userRepository = $userRepository;
    }

    public function checkCredentialsAndGetUser(array $jsonData): User
    {
        if (!(isset($jsonData['username']) && isset($jsonData['password']))) {
            throw new AppException('Bad credentials', 406);
        }

        $user = $this->userRepository->findOneBy(['username' => $jsonData['username']]);

        if (!$user) {
            throw new AppException('Bad credentials', 406);
        }

        if (!$this->passwordEncoder->isPasswordValid($user, $jsonData['password'])) {
            throw new AppException('Bad credentials', 406);
        }

        return $user;
    }

    public function checkAdminRights(User $user)
    {
        if (count(array_intersect(['ROLE_ADMIN', 'ROLE_SUPER_ADMIN'], $user->getRoles())) === 0) {
            throw new AppException('Not enough rights', 406);
        }
    }

    public function checkSuperAdminRights(User $user)
    {
        if (count(array_intersect(['ROLE_SUPER_ADMIN'], $user->getRoles())) === 0) {
            throw new AppException('Not enough rights', 406);
        }
    }

    public function isBlockedUser(User $user)
    {
        if ((count(array_intersect(['ROLE_SUPER_ADMIN'], $user->getRoles())) === 0) && !$user->isActive()) {
            throw new AppException('Your account is blocked', 406);
        }
    }
}