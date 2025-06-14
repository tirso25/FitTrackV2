<?php

namespace App\Service;

use Symfony\Component\HttpFoundation\Response;

class FavouritesCoachsService
{
    public function getFavouriteCoachsByUserId(int $id, $entityManager)
    {
        $query = $entityManager->createQuery(
            'SELECT fc, c
            FROM App\Entity\FavoritesCoachs fc
            JOIN fc.user c
            WHERE fc.user = :id_user AND c.public = true'
        )->setParameter('id_user', $id);

        $favorites = $query->getResult();

        $data = [];

        if (empty($favorites)) {
            $data = ['type' => 'warning', 'message' => 'This user has a private profile or no bookmarks', Response::HTTP_BAD_REQUEST];
            return $data;
        }

        foreach ($favorites as $favourite) {
            $coach = $favourite->getCoach();
            $likes = $coach->getCoachLikes()?->getLikes() ?? 0;
            $data[] = [
                'type' => 'success',
                'message' => [
                    'coach_id' => $coach->getUserId(),
                    'coach_name' => $coach->getDisplayUsername(),
                    'coach_description' => $coach->getDescription(),
                    'likes_ch' => $likes
                ]
            ];
        }

        return $data;
    }

    public function getFavouriteCoachs(int $id, $entityManager)
    {
        $query = $entityManager->createQuery(
            'SELECT fc, c
            FROM App\Entity\FavoritesCoachs fc
            JOIN fc.user c
            WHERE fc.user = :id_user'
        )->setParameter('id_user', $id);

        $favorites = $query->getResult();

        $data = [];

        if (empty($favorites)) {
            $data = ['type' => 'warning', 'message' => 'This user has a private profile or no bookmarks', Response::HTTP_BAD_REQUEST];
            return $data;
        }

        foreach ($favorites as $favourite) {
            $coach = $favourite->getCoach();
            $likes = $coach->getCoachLikes()?->getLikes() ?? 0;
            $data[] = [
                'type' => 'success',
                'message' => [
                    'coach_id' => $coach->getUserId(),
                    'coach_name' => $coach->getDisplayUsername(),
                    'coach_description' => $coach->getDescription(),
                    'likes_ch' => $likes
                ]
            ];
        }

        return $data;
    }
}
