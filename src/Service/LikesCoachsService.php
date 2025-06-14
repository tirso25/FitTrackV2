<?php

namespace App\Service;

class LikesCoachsService
{
    public function getCoachsLikes($entityManager, $id)
    {
        $query = $entityManager->createQuery(
            "SELECT lc.likes
            FROM App\Entity\LikesCoachs lc
            WHERE lc.coach = :id"
        )->setParameter('id', $id);

        return $query->getResult();
    }
}
