<?php

namespace App\Controller;

use App\Entity\Users;
use App\Service\CoachService;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Routing\Attribute\Route;
use App\Service\GlobalService;
use App\Service\LikesCoachsService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;

#[Route('/api/coachs')]
class CoachsController extends AbstractController
{
    public function __construct(
        private CoachService $coachService,
        private GlobalService $globalService,
        private LikesCoachsService $likesCoachsService
    ) {}

    #[Route('/seeAllCoachs', name: 'api_seeAllCoachs', methods: ['GET'])]
    public function seeAllCoachs(EntityManagerInterface $entityManager): JsonResponse
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

        $coachs = $this->coachService->seeAllCoachs($entityManager);

        if (!$coachs) {
            return $this->json(['type' => 'warning', 'message' => 'No coachs found'], Response::HTTP_BAD_REQUEST);
        }

        $data = [];

        foreach ($coachs as $coach) {
            $likes = $this->likesCoachsService->getCoachsLikes($entityManager, $coach->getUserId());
            $data[] = [
                'id_ch' => $coach->getUserId(),
                'email' => $coach->getEmail(),
                'username' => $coach->getDisplayUsername(),
                'description' => $coach->getDescription(),
                'likes' => $likes,
            ];
        }

        return $this->json($data, Response::HTTP_OK);
    }

    #[Route('/seeAllExercisesByCoach/{id<\d+>}', name: 'api_seeAllExercisesByCoach', methods: ['GET'])]
    public function seeAllExercisesByCoach(EntityManagerInterface $entityManager, int $id): JsonResponse
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

        $coach = $entityManager->find(Users::class, $id);

        if (!$coach) {
            return $this->json(['type' => 'warning', 'message' => 'No coachs found'], Response::HTTP_BAD_REQUEST);
        }

        if ($coach->getRole()->getName() !== "ROLE_COACH") {
            return $this->json(['type' => 'warning', 'message' => 'The user is not coach'], Response::HTTP_BAD_REQUEST);
        }

        if ($coach->getStatus() !== "active") {
            return $this->json(['type' => 'warning', 'message' => 'The coach is not active'], Response::HTTP_BAD_REQUEST);
        }

        $exercises = $this->coachService->seeAllExercisesByCoach($entityManager, $id);

        $exercisesByCoach = [];

        foreach ($exercises as $exercise) {
            $likes = $exercise->getExerciseLikes()?->getLikes() ?? 0;
            $exercisesByCoach[] = [
                'exercise_id' => $exercise->getExerciseId(),
                'coach_id' => $exercise->getUser()->getUserId(),
                'coach' => $exercise->getUser()->getDisplayUsername(),
                'exercise_name' => $exercise->getName(),
                'exercise_description' => $exercise->getDescription(),
                'exercise_category_id' => $exercise->getCategory()->getCategoryId(),
                'exercise_category_name' => $exercise->getCategory()->getName(),
                'exercise_created_at' => $exercise->getCreatedAt(),
                'exercise_likes' => $likes,
            ];
        }

        return $this->json($exercisesByCoach, Response::HTTP_OK);
    }
}
