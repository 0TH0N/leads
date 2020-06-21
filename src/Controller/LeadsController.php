<?php

namespace App\Controller;

use App\Entity\Lead;
use App\Exception\AppException;
use App\Repository\LeadRepository;
use App\Repository\UserRepository;
use App\Traits\SecurityTrait;
use Doctrine\ORM\EntityManagerInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;

class LeadsController
{
    use SecurityTrait;
    /**
     * @var EntityManagerInterface
     */
    private $entityManager;
    /**
     * @var UserRepository
     */
    private $userRepository;
    /**
     * @var LeadRepository
     */
    private $leadRepository;
    /**
     * @var UserPasswordEncoderInterface
     */
    private $passwordEncoder;
    /**
     * @var LoggerInterface
     */
    private $logger;

    /**
     * LeadsController constructor.
     *
     * @param EntityManagerInterface       $entityManager
     * @param UserRepository               $userRepository
     * @param LeadRepository               $leadRepository
     * @param UserPasswordEncoderInterface $passwordEncoder
     * @param LoggerInterface              $logger
     */
    public function __construct(
        EntityManagerInterface $entityManager,
        UserRepository $userRepository,
        LeadRepository $leadRepository,
        UserPasswordEncoderInterface $passwordEncoder,
        LoggerInterface $logger
    )
    {
        $this->entityManager = $entityManager;
        $this->userRepository = $userRepository;
        $this->leadRepository = $leadRepository;
        $this->passwordEncoder = $passwordEncoder;
        $this->logger = $logger;
    }

    /**
     * Создание нового лида
     * @param Request $request
     *
     * @return JsonResponse
     */
    public function new(Request $request)
    {
        try {
            if (stripos($request->getContentType(), 'application/json') !== false) {
                throw new AppException('Need JSON format for request.', 400);
            }

            if ($request->getMethod() !== 'POST') {
                throw new AppException('Need POST request method.', 400);
            }

            $jsonData = json_decode($request->getContent(), true);
            $user = $this->checkCredentialsAndGetUser($jsonData);
            $this->isBlockedUser($user);

            if (!isset($jsonData['name']) || !isset($jsonData['sourceId']) || !isset($jsonData['status'])) {
                throw new AppException("Some fields doesn't specified.", 406);
            }

            $lead = new Lead($user, $jsonData['name'], $jsonData['sourceId'], $jsonData['status']);
            $this->entityManager->persist($lead);
            $this->entityManager->flush();

            return new JsonResponse([
                'status'  => 'success',
                'message' => 'Lead successfully added.',
            ], 201);

        } catch (AppException $exception) {
            $this->logger->error($exception->getMessage(), ['ip' => $request->getClientIp()]);
            return new JsonResponse([
                'status'  => 'error',
                'message' => $exception->getMessage(),
            ], $exception->getCode());
        }
    }

    public function get(Request $request)
    {
        try {
            if (stripos($request->getContentType(), 'application/json') !== false) {
                throw new AppException('Need JSON format for request.', 400);
            }

            if ($request->getMethod() !== 'GET') {
                throw new AppException('Need GET request method.', 400);
            }

            $jsonData = json_decode($request->getContent(), true);
            $user = $this->checkCredentialsAndGetUser($jsonData);
            $this->isBlockedUser($user);
            $size = isset($jsonData['pageSize']) ? (int) $jsonData['pageSize'] : 20;
            $page = isset($jsonData['pageNumber']) ? (int) $jsonData['pageNumber'] : 0;
            $users = isset($jsonData['filterUsers']) ? (array) $jsonData['filterUsers'] : [];
            $statuses = isset($jsonData['filterStatus']) ? (array) $jsonData['filterStatus'] : [];

            if ($user->isAdmin()) {
                $users = count($users) > 0 ? $this->userRepository->findByUsernames($users) : [];
                $result = $this->leadRepository->getFilteredLeads($size, $page, false, $users, $statuses);
                $total = $this->leadRepository->getFilteredLeads($size, $page, true, $users, $statuses);
            } else {
                $result = $this->leadRepository->getFilteredLeads($size, $page, false, [$user], $statuses);
                $total = $this->leadRepository->getFilteredLeads($size, $page, true, [$user], $statuses);
            }

            return new JsonResponse([
                'status'      => 'success',
                'message'     => 'Leads successfully received.',
                'result'      => $result,
                'total_count' => $total,
            ], 200);

        } catch (AppException $exception) {
            $this->logger->error($exception->getMessage(), ['ip' => $request->getClientIp()]);
            return new JsonResponse([
                'status'  => 'error',
                'message' => $exception->getMessage(),
            ], $exception->getCode());
        }
    }
}
