<?php

namespace App\Controller;

use App\Exception\AppException;
use App\Entity\User;
use App\Repository\UserRepository;
use App\Traits\SecurityTrait;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;

class UserController
{
    use SecurityTrait;

    /**
     * @var EntityManagerInterface
     */
    private $entityManager;
    /**
     * @var UserPasswordEncoderInterface
     */
    private $passwordEncoder;
    /**
     * @var UserRepository
     */
    private $userRepository;
    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * DefaultController constructor.
     *
     * @param EntityManagerInterface       $entityManager
     * @param UserPasswordEncoderInterface $passwordEncoder
     * @param UserRepository               $userRepository
     * @param LoggerInterface              $logger
     */
    public function __construct(
        EntityManagerInterface $entityManager,
        UserPasswordEncoderInterface $passwordEncoder,
        UserRepository $userRepository,
        LoggerInterface $logger
    )
    {
        $this->entityManager = $entityManager;
        $this->passwordEncoder = $passwordEncoder;
        $this->userRepository = $userRepository;
        $this->logger = $logger;
    }

    /**
     * Добавление первого пользователя в базу с правами Супер-Админа.
     *
     * @param Request $request
     *
     * @return JsonResponse|Response
     */
    public function addFirstRootUser(Request $request)
    {
        try {
            if (stripos($request->getContentType(), 'application/json') !== false) {
                throw new AppException('Need JSON format for request.', 400);
            }

            // Получение самого первого пользователя-админа.
            $rootUser = $this->userRepository->getRootUser();

            if ($rootUser) {
                throw new AppException('Root user already exist.', 406);
            }

            $jsonData = json_decode($request->getContent(), true);
            $this->checkUsernameStrength($jsonData['username']);
            $this->checkPasswordStrength($jsonData['password']);
            $rootUser = new User();
            $rootUser
                ->setUsername($jsonData['username'])
                ->setPassword($this->passwordEncoder->encodePassword($rootUser, $jsonData['password']))
                ->setRoles(['ROLE_SUPER_ADMIN']);
            $this->entityManager->persist($rootUser);
            $this->entityManager->flush();

            return new JsonResponse([
                'status'  => 'success',
                'message' => 'Root user ' . $rootUser->getUsername() . ' successfully added.',
            ], 201);
        } catch (AppException $exception) {
            $this->logger->error($exception->getMessage(), ['ip' => $request->getClientIp()]);
            return new JsonResponse([
                'status'  => 'error',
                'message' => $exception->getMessage(),
            ], $exception->getCode());
        }
    }

    /**
     * @param Request $request
     *
     * @return JsonResponse
     */
    public function addUser(Request $request)
    {
        try {
            if (stripos($request->getContentType(), 'application/json') !== false) {
                throw new AppException('Need JSON format for request.', 400);
            }

            $jsonData = json_decode($request->getContent(), true);
            $admin = $this->checkCredentialsAndGetUser($jsonData);
            $this->isBlockedUser($admin);
            $isAdminNewUser = isset($jsonData['newAdmin']) && $jsonData['newAdmin'] == true;

            if ($isAdminNewUser) {
                $this->checkSuperAdminRights($admin);
            } else {
                $this->checkAdminRights($admin);
            }

            if ($this->userRepository->findOneBy(['username' => $jsonData['newUsername']])) {
                throw new AppException("User {$jsonData['newUsername']} already exist.", 406);
            }

            $this->checkUsernameStrength($jsonData['newUsername']);
            $this->checkPasswordStrength($jsonData['newPassword']);
            $rootUser = new User();
            $rootUser->setUsername($jsonData['newUsername']);
            $rootUser->setPassword($this->passwordEncoder->encodePassword($rootUser, $jsonData['newPassword']));

            if ($isAdminNewUser) {
                $rootUser->setRoles(['ROLE_ADMIN']);
            }

            $this->entityManager->persist($rootUser);
            $this->entityManager->flush();

            return new JsonResponse([
                'status'  => 'success',
                'message' => 'User ' . $rootUser->getUsername() . ' successfully added.',
            ], 201);
        } catch (AppException $exception) {
            $this->logger->error($exception->getMessage(), ['ip' => $request->getClientIp()]);
            return new JsonResponse([
                'status'  => 'error',
                'message' => $exception->getMessage(),
            ], $exception->getCode());
        }
    }

    /**
     * @param Request $request
     *
     * @return JsonResponse
     */
    public function blockUser(Request $request)
    {
        try {
            if (stripos($request->getContentType(), 'application/json') !== false) {
                throw new AppException('Need JSON format for request.', 400);
            }

            $jsonData = json_decode($request->getContent(), true);
            $admin = $this->checkCredentialsAndGetUser($jsonData);
            $this->isBlockedUser($admin);
            $this->checkAdminRights($admin);
            $blockedUser = $this->userRepository->findOneBy(['username' => $jsonData['blockedUsername']]);

            if (!$blockedUser) {
                throw new AppException("User {$jsonData['blockedUsername']} doesn't exist.", 406);
            }

            $blockedUser->setIsActive(false);
            $this->entityManager->flush();

            return new JsonResponse([
                'status'  => 'success',
                'message' => 'User ' . $blockedUser->getUsername() . ' successfully blocked.',
            ], 200);
        } catch (AppException $exception) {
            $this->logger->error($exception->getMessage(), ['ip' => $request->getClientIp()]);
            return new JsonResponse([
                'status'  => 'error',
                'message' => $exception->getMessage(),
            ], $exception->getCode());
        }
    }

    /**
     * @param Request $request
     *
     * @return JsonResponse
     */
    public function unblockUser(Request $request)
    {
        try {
            if (stripos($request->getContentType(), 'application/json') !== false) {
                throw new AppException('Need JSON format for request.', 400);
            }

            $jsonData = json_decode($request->getContent(), true);
            $admin = $this->checkCredentialsAndGetUser($jsonData);
            $this->isBlockedUser($admin);
            $this->checkAdminRights($admin);
            $blockedUser = $this->userRepository->findOneBy(['username' => $jsonData['unblockedUsername']]);

            if (!$blockedUser) {
                throw new AppException("User {$jsonData['unblockedUsername']} doesn't exist.", 406);
            }

            $blockedUser->setIsActive(true);
            $this->entityManager->flush();

            return new JsonResponse([
                'status'  => 'success',
                'message' => 'User ' . $blockedUser->getUsername() . ' successfully unblocked.',
            ], 200);
        } catch (AppException $exception) {
            $this->logger->error($exception->getMessage(), ['ip' => $request->getClientIp()]);
            return new JsonResponse([
                'status'  => 'error',
                'message' => $exception->getMessage(),
            ], $exception->getCode());
        }
    }

    /**
     * @param string $username
     *
     * @throws AppException
     */
    private function checkUsernameStrength(string $username)
    {
        if (strlen($username) < 4) {
            throw new AppException("Username must to be 4 chars at minimum.", 406);
        }
    }

    /**
     * @param string $password
     *
     * @throws AppException
     */
    private function checkPasswordStrength(string $password)
    {
        $error = [];

        if (strlen($password) < 8 ) {
            $error[] = "Password too short.";
        }

        if (strlen($password) > 20 ) {
            $error[] = "Password too long.";
        }

        if (!preg_match("#[0-9]+#", $password) ) {
            $error[] = "Password must include at least one number.";
        }

        if (!preg_match("#[a-z]+#", $password) ) {
            $error[] = "Password must include at least one letter.";
        }

        if (!preg_match("#[A-Z]+#", $password) ) {
            $error[] = "Password must include at least one CAPS.";
        }

        if (!preg_match("#\W+#", $password) ) {
            $error[] = "Password must include at least one symbol.";
        }

        if (count($error) > 0) {
            throw new AppException(implode(' ', $error), 406);
        }
    }
}