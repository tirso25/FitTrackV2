<?php

namespace App\Service;

use Symfony\Component\HttpFoundation\Response;

class FavoritesExercisesService
{
    public function getFavouriteExercisesByUserId(int $id, $entityManager)
    {
        $query = $entityManager->createQuery(
            'SELECT fe
            FROM App\Entity\FavoritesExercises fe
            JOIN fe.user u
            WHERE fe.user = :id_user AND u.public = true'
        )->setParameter('id_user', $id);

        $favorites = $query->getResult();

        $data = [];

        if (empty($favorites)) {
            $data = ['type' => 'warning', 'message' => 'This user has a private profile or no bookmarks', Response::HTTP_BAD_REQUEST];
        }

        foreach ($favorites as $favourite) {
            $likes = $favourite->getExercise()->getExerciseLikes()?->getLikes() ?? 0;
            $data[] = [
                'type' => 'success',
                'message' => [
                    'id_exe' => $favourite->getExercise()->getExerciseId(),
                    'name_exe' => $favourite->getExercise()->getName(),
                    'description_exe' => $favourite->getExercise()->getDescription(),
                    'category_exe' => $favourite->getExercise()->getCategory()->getName(),
                    'likes_exe' => $likes
                ]
            ];
        }

        return $data;
    }

    public function getFavouriteExercises(int $id, $entityManager)
    {
        $query = $entityManager->createQuery(
            'SELECT fe
            FROM App\Entity\FavoritesExercises fe
            JOIN fe.user u
            WHERE fe.user = :id_user'
        )->setParameter('id_user', $id);

        $favorites = $query->getResult();

        $data = [];

        if (empty($favorites)) {
            $data = ['type' => 'warning', 'message' => 'You have no exercises added to favorites', Response::HTTP_BAD_REQUEST];
        }

        foreach ($favorites as $favourite) {
            $likes = $favourite->getExercise()->getExerciseLikes()?->getLikes() ?? 0;
            $data[] = [
                'type' => 'success',
                'message' => [
                    'id_exe' => $favourite->getExercise()->getExerciseId(),
                    'name_exe' => $favourite->getExercise()->getName(),
                    'description_exe' => $favourite->getExercise()->getDescription(),
                    'category_exe' => $favourite->getExercise()->getCategory()->getName(),
                    'likes_exe' => $likes
                ]
            ];
        }

        return $data;
    }
}
