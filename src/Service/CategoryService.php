<?php

namespace App\Service;

class CategoryService
{
    public function categoryExisting($nameORid, $entityManager)
    {
        $category = $entityManager->createQuery(
            'SELECT c
            FROM App\Entity\Categories c 
            WHERE c.category_id = :nameORid OR c.name = :nameORid'
        )->setParameter('nameORid', $nameORid);;

        return $category->getOneOrNullResult();
    }

    public function categoryExisting2(int $id, string $name, $entityManager)
    {
        $query2 = $entityManager->createQuery(
            'SELECT c.name 
            FROM App\Entity\Categories c 
            WHERE c.category_id = :id'
        )->setParameter('id', $id);

        $result = $query2->getOneOrNullResult();

        if (!$result || !isset($result['name'])) {
            return false;
        }

        $nameDB = $result['name'];

        $query = $entityManager->createQuery(
            'SELECT c 
            FROM App\Entity\Categories c 
            WHERE c.name = :name AND c.name != :nameDB'
        )->setParameters([
            'name' => $name,
            'nameDB' => $nameDB
        ]);

        return $query->getOneOrNullResult() !== null;
    }
}
