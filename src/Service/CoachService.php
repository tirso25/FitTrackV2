<?php

namespace App\Service;

use App\Entity\Users;

class CoachService
{
    public function seeAllCoachs($entityManager)
    {
        $query = $entityManager->createQuery(
            "SELECT u
            FROM App\Entity\Users u
            WHERE u.role = 3"
        );

        return $query->getResult();
    }

    public function seeAllActiveCoachs($entityManager)
    {
        $query = $entityManager->createQuery(
            "SELECT u
            FROM App\Entity\Users u
            WHERE u.role = 3
            AND u.status = 'active'"
        );

        return $query->getResult();
    }

    public function isActive($entityManager, $id)
    {
        $query = $entityManager->createQuery(
            "SELECT c 
            FROM App\Entity\Users c 
            WHERE c.user_id = :id AND c.status = 'active'"
        )->setParameter('id', $id);

        return $query->getOneOrNullResult() !== null;
    }

    public function seeAllExercisesByCoach($entityManager, int $coach_id)
    {
        $user = $entityManager->getRepository(Users::class)->find($coach_id);

        $query = $entityManager->createQuery(
            "SELECT e
            FROM App\Entity\Exercises e
            WHERE e.user = :coach
            AND e.active = 1"
        )->setParameter('coach', $user);

        return $query->getResult();
    }
}
