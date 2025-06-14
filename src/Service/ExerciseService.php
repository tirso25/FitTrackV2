<?php

namespace App\Service;

class ExerciseService
{
    public function exerciseExisting2(int $id, string $name,  $entityManager)
    {
        $query2 = $entityManager->createQuery(
            'SELECT e.name 
            FROM App\Entity\Exercises e 
            WHERE e.exercise_id = :id'
        )->setParameter('id', $id);

        $result = $query2->getOneOrNullResult();

        if (!$result || !isset($result['name'])) {
            return false;
        }

        $nameDB = $result['name'];

        $query = $entityManager->createQuery(
            'SELECT e
            FROM App\Entity\Exercises e 
            WHERE e.name = :name AND e.name != :nameDB'
        )->setParameters([
            'name' => $name,
            'nameDB' => $nameDB
        ]);

        return $query->getOneOrNullResult() !== null;
    }

    public function isActive(int $id,  $entityManager)
    {
        $query = $entityManager->createQuery(
            'SELECT e 
            FROM App\Entity\Exercises e 
            WHERE e.exercise_id = :id AND e.active = true'
        )->setParameter('id', $id);

        return $query->getOneOrNullResult() !== null;
    }
}
