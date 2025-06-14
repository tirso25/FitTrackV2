<?php

namespace App\Controller;

use App\Entity\Exercises;
use App\Entity\FavoritesExercises;
use App\Service\ExerciseService;
use App\Service\FavoritesExercisesService;
use App\Service\GlobalService;
use App\Service\UserService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\HttpFoundation\Response;

//!VER NUEVOS CAMBIOS CON PUBLIC (perfil publico)

#[Route('/api/favoriteExercises')]
class FavoritesExercisesController extends AbstractController
{
    public function __construct(
        private UserService $userService,
        private GlobalService $globalService,
        private FavoritesExercisesService $favoriteExercisesService,
        private ExerciseService $exerciseService,
    ) {}

    #[Route('/seeFavoritesExercises', name: 'api_seeFavoritesExercises', methods: ['GET'])]
    public function seeAllFavouritesExercises(EntityManagerInterface $entityManager): JsonResponse
    {
        /** @var \App\Entity\Users $thisuser */
        $thisuser = $this->getUser();

        if (!$thisuser) {
            return $this->json(['type' => 'error', 'message' => 'You are not logged in'], Response::HTTP_UNAUTHORIZED);
        }

        $thisuserId = $thisuser->getUserId();
        $thisuserStatus = $thisuser->getStatus();

        if ($thisuserStatus !== 'active') {
            $this->globalService->forceSignOut($entityManager, $thisuserId);
            return $this->json(['type' => 'error', 'message' => 'You are not active'], Response::HTTP_UNAUTHORIZED);
        }

        $favourites = $this->favoriteExercisesService->getFavouriteExercises($thisuserId, $entityManager);

        return $this->json($favourites, Response::HTTP_OK);
    }

    #[Route('/addFavoriteExercise/{id<\d+>}', name: 'api_addFavoriteExercise', methods: ['POST'])]
    public function addExerciseFavourite(EntityManagerInterface $entityManager, int $id): JsonResponse
    {
        /** @var \App\Entity\Users $thisuser */
        $thisuser = $this->getUser();

        if (!$thisuser) {
            return $this->json(['type' => 'error', 'message' => 'You are not logged in'], Response::HTTP_UNAUTHORIZED);
        }

        $thisuserId = $thisuser->getUserId();
        $thisuserStatus = $thisuser->getStatus();

        if ($thisuserStatus !== 'active') {
            $this->globalService->forceSignOut($entityManager, $thisuserId);
            return $this->json(['type' => 'error', 'message' => 'You are not active'], Response::HTTP_UNAUTHORIZED);
        }

        $exercise = $this->exerciseService->isActive($id, $entityManager);

        if (!$exercise) {
            return $this->json(['type' => 'error', 'message' => 'The exercise does not exist'], Response::HTTP_BAD_REQUEST);
        }

        $thisExercise = $entityManager->find(Exercises::class, $id);

        $existing = $entityManager->getRepository(FavoritesExercises::class)->findOneBy(['user' => $thisuser, 'exercise' => $thisExercise]);

        if ($existing) {
            return $this->json(['type' => 'warning', 'message' => 'Exercise already added to favorite'], Response::HTTP_BAD_REQUEST);
        }

        $newFavourite = new FavoritesExercises();

        $newFavourite->setUser($thisuser);
        $newFavourite->setExercise($thisExercise);
        $newFavourite->setActive(true);

        $entityManager->persist($newFavourite);
        $entityManager->flush();

        return $this->json(['type' => 'success', 'message' => 'Exercise added to favorite correctly'], Response::HTTP_OK);
    }

    #[Route('/undoFavorite/{id<\d+>}', name: 'api_undoFavorite', methods: ['DELETE'])]
    public function undoFavorite(EntityManagerInterface $entityManager, int $id): JsonResponse
    {
        /** @var \App\Entity\Users $thisuser */
        $thisuser = $this->getUser();

        if (!$thisuser) {
            return $this->json(['type' => 'error', 'message' => 'You are not logged in'], Response::HTTP_UNAUTHORIZED);
        }

        $thisuserId = $thisuser->getUserId();
        $thisuserStatus = $thisuser->getStatus();

        if ($thisuserStatus !== 'active') {
            $this->globalService->forceSignOut($entityManager, $thisuserId);
            return $this->json(['type' => 'error', 'message' => 'You are not active'], Response::HTTP_UNAUTHORIZED);
        }

        $favourite =  $entityManager->getRepository(FavoritesExercises::class)->findOneBy(['user' => $thisuserId, 'exercise' => $id]);

        if (!$favourite) {
            return $this->json(['type' => 'error', 'message' => 'You have not added this exercise to your favorites or this exercise does not exist'], Response::HTTP_BAD_REQUEST);
        }

        $entityManager->remove($favourite);
        $entityManager->flush();

        return $this->json(['type' => 'success', 'message' => 'Exercise successfully removed from favorites'], Response::HTTP_OK);
    }
}
