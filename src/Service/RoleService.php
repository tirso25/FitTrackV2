<?php

namespace App\Service;

class RoleService
{
    public function roleExisting($nameORid, $entityManager)
    {

        $role = $entityManager->createQuery(
            "SELECT r 
            FROM App\Entity\Roles r 
            WHERE r.role_id = :nameORid OR r.name = :nameORid"
        )->setParameter('nameORid', $nameORid);

        return $role->getOneOrNullResult();
    }

    public function roleExisting2(int $id, string $name, $entityManager)
    {
        $query2 = $entityManager->createQuery(
            'SELECT r.name
            FROM App\Entity\Roles r 
            WHERE r.role_id = :id'
        )->setParameter('id', $id);

        $result = $query2->getOneOrNullResult();

        if (!$result || !isset($result['name'])) {
            return false;
        }

        $nameDB = $result['name'];

        $query = $entityManager->createQuery(
            'SELECT r 
            FROM App\Entity\Roles r 
            WHERE r.name = :name AND r.name != :nameDB'
        )->setParameters([
            'name' => $name,
            'nameDB' => $nameDB
        ]);

        return $query->getOneOrNullResult() !== null;
    }

    public function seeAllRoles($entityManager)
    {
        $query = $entityManager->createQuery(
            'SELECT r
            FROM App\Entity\Roles r
            WHERE r.role_id != 1'
        );

        return $query->getResult();
    }
}
