<?php

namespace App\Service;

use App\Entity\Users;

//!VER COMO DISMINUIR / JUNTAR LOS userExisting*
class UserService
{
    public function removeToken($entityManager, int $id_user)
    {
        $user = $entityManager->find(Users::class, $id_user);

        $user->setToken(null);

        $entityManager->persist($user);
        $entityManager->flush();
    }

    public function hashPassword(string $password)
    {
        $options = [
            'cost' => 13,
        ];

        return password_hash($password, PASSWORD_BCRYPT, $options);
    }

    public function userExisting($emailUsernameId, $entityManager)
    {
        $query = $entityManager->createQuery(
            "SELECT u 
            FROM App\Entity\Users u 
            WHERE u.email = :emailUsernameId OR u.username = :emailUsernameId OR u.user_id = :emailUsernameId"
        )->setParameter('emailUsernameId', $emailUsernameId);

        return $query->getOneOrNullResult();
    }

    public function userExisting2(int $id, string $username, $entityManager)
    {
        $query2 = $entityManager->createQuery(
            'SELECT u.username 
            FROM App\Entity\Users u 
            WHERE u.user_id = :id'
        )->setParameter('id', $id);

        $result = $query2->getOneOrNullResult();

        if (!$result || !isset($result['username'])) {
            return false;
        }

        $usernameDB = $result['username'];

        $query = $entityManager->createQuery(
            'SELECT u
            FROM App\Entity\Users u 
            WHERE u.username = :username AND u.username != :usernameDB'
        )->setParameters([
            'username' => $username,
            'usernameDB' => $usernameDB
        ]);

        return $query->getOneOrNullResult() !== null;
    }

    public function userExisting3(string $email, string $username, $entityManager): bool
    {
        $query = $entityManager->createQuery(
            "SELECT u 
            FROM App\Entity\Users u 
            WHERE u.email = :email OR u.username = :username"
        )
            ->setParameter('email', $email)
            ->setParameter('username', $username);

        return $query->getOneOrNullResult() !== null;
    }

    public function checkState($entityManager, int $userId)
    {
        if ($userId === null) {
            return false;
        }

        $user = $entityManager->find(Users::class, $userId);

        return ($user->getStatus());
    }

    public function seeAllUsers($entityManager)
    {
        $query = $entityManager->createQuery(
            "SELECT u
            FROM App\Entity\Users u
            WHERE u.role != 1"
        );

        return $query->getResult();
    }
}
