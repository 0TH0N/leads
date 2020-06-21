<?php

namespace App\Repository;

use App\Entity\Lead;
use Doctrine\Bundle\DoctrineBundle\Repository\ServiceEntityRepository;
use Doctrine\Persistence\ManagerRegistry;

/**
 * @method Lead|null find($id, $lockMode = null, $lockVersion = null)
 * @method Lead|null findOneBy(array $criteria, array $orderBy = null)
 * @method Lead[]    findAll()
 * @method Lead[]    findBy(array $criteria, array $orderBy = null, $limit = null, $offset = null)
 */
class LeadRepository extends ServiceEntityRepository
{
    public function __construct(ManagerRegistry $registry)
    {
        parent::__construct($registry, Lead::class);
    }

    public function getFilteredLeads(
        int $pageSize,
        int $pageNumber,
        bool $needCalcCount,
        array $users = [],
        array $statuses = []
    )
    {
        $qb = $this->createQueryBuilder('l');

        if ($needCalcCount) {
            $qb->select('COUNT(l)');
        } else {
            $qb->select('l')
                ->setFirstResult($pageNumber)
                ->setMaxResults($pageSize)
                ->orderBy('l.id', 'ASC');
        }

        if (count($users) > 0) {
            $qb
                ->andWhere('l.created_by IN (:users)')
                ->setParameter('users', $users);
        }

        if (count($statuses) > 0) {
            $qb
                ->andWhere('l.status IN (:statuses)')
                ->setParameter('statuses', $statuses);
        }

        return $needCalcCount ? $qb->getQuery()->getSingleScalarResult() : $qb->getQuery()->getArrayResult();
    }
}
