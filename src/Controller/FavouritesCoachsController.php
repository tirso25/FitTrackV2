<?php

namespace App\Controller;

use App\Entity\FavoritesCoachs;
use App\Entity\Users;
use App\Service\CoachService;
use App\Service\FavouritesCoachsService;
use App\Service\GlobalService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\HttpFoundation\Response;

#[Route('/api/favoriteCoachs')]
class FavouritesCoachsController extends AbstractController
{
    public function __construct(
        private CoachService $coachService,
        private GlobalService $globalService,
        private FavouritesCoachsService $favouritesCoachsService
    ) {}

    #[Route('/seeFavoritesCoachs', name: 'api_seeFavoritesCoachs', methods: ['GET'])]
    public function seeFavoritesCoachs(EntityManagerInterface $entityManager): JsonResponse
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

        $favourites = $this->favouritesCoachsService->getFavouriteCoachs($thisuserId, $entityManager);

        return $this->json($favourites, Response::HTTP_OK);
    }

    #[Route('/addFavoritesCoachs/{id<\d+>}', name: 'addFavoritesCoachs', methods: ['POST'])]
    public function addFavoritesCoachs(EntityManagerInterface $entityManager, int $id)
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

        $coach = $this->coachService->isActive($entityManager, $id);

        if (!$coach) {
            return $this->json(['type' => 'error', 'message' => 'The coach is not active'], Response::HTTP_BAD_REQUEST);
        }

        $thisCoach = $entityManager->find(Users::class, $id);

        $existing = $entityManager->getRepository(FavoritesCoachs::class)->findOneBy(['user' => $thisuser, 'coach' => $thisCoach]);

        if ($existing) {
            return $this->json(['type' => 'warning', 'message' => 'Coach already added to favorite'], Response::HTTP_BAD_REQUEST);
        }

        $newFavourite = new FavoritesCoachs();

        $newFavourite->setUser($thisuser);
        $newFavourite->setCoach($thisCoach);
        $newFavourite->setActive(true);

        $entityManager->persist($newFavourite);
        $entityManager->flush();

        return $this->json(['type' => 'success', 'message' => 'Coach added to favorite correctly'], Response::HTTP_OK);
    }

    #[Route('/undoFavoritesCoachs/{id<\d+>}', name: 'undoFavoritesCoachs', methods: ['DELETE'])]
    public function undoFavoritesCoachs(EntityManagerInterface $entityManager, int $id): JsonResponse
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

        $thisCoach = $entityManager->find(Users::class, $id);

        $favourite = $entityManager->getRepository(FavoritesCoachs::class)->findOneBy(['user' => $thisuser, 'coach' => $thisCoach]);

        if (!$favourite) {
            return $this->json(['type' => 'error', 'message' => 'You have not added this coach to your favorites or this coach does not exist'], Response::HTTP_BAD_REQUEST);
        }

        $entityManager->remove($favourite);
        $entityManager->flush();

        return $this->json(['type' => 'success', 'message' => 'Coach successfully removed from favorites'], Response::HTTP_OK);
    }
}
