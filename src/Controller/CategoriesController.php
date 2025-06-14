<?php

namespace App\Controller;

use App\Entity\Categories;
use App\Service\CategoryService;
use App\Service\GlobalService;
use App\Service\UserService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\HttpFoundation\Response;

#[Route('/api/categories')]
class CategoriesController extends AbstractController
{
    public function __construct(
        private UserService $userService,
        private GlobalService $globalService,
        private CategoryService $categoryService
    ) {}

    #[Route('/seeAllCategories', name: 'api_seeAllCategories', methods: ['GET'])]
    public function seeAllCategories(EntityManagerInterface $entityManager): JsonResponse
    {
        /** @var \App\Entity\Users $thisuser */
        $thisuser = $this->getUser();

        if (!$thisuser) {
            return $this->json(['type' => 'error', 'message' => 'You are not logged in'], Response::HTTP_UNAUTHORIZED);
        }

        $thisuserId = $thisuser->getUserId();
        $thisuserRole = $thisuser->getRole()->getName();
        $thisuserStatus = $thisuser->getStatus();

        if ($thisuserStatus !== 'active') {
            $this->globalService->forceSignOut($entityManager, $thisuserId);
            return $this->json(['type' => 'error', 'message' => 'You are not active'], Response::HTTP_UNAUTHORIZED);
        }

        if (!in_array($thisuserRole, ["ROLE_ADMIN", "ROLE_COACH"])) {
            return $this->json(['type' => 'error', 'message' => 'You are not an administrator or a coach'], Response::HTTP_BAD_REQUEST);
        }

        $categories = $entityManager->getRepository(Categories::class)->findAll();

        if (!$categories) {
            return $this->json(['type' => 'warning', 'message' => 'No categories found'], Response::HTTP_BAD_REQUEST);
        }

        $categoriesData = [];

        foreach ($categories as $data) {
            $categoriesData[] = [
                'id' => $data->getCategoryId(),
                'name' => $data->getName(),
                'active' => $data->getActive()
            ];
        }

        return $this->json($categoriesData, Response::HTTP_OK);
    }

    //!SE CREA POS SI SE QUIERE CONSUMIR COMO API, NO SE USA EN EL FRONT
    #[Route('/seeOneCategory/{id<\d+>}', name: 'seeOneCategory', methods: ['GET'])]
    public function seeOneCategory(EntityManagerInterface $entityManager, int $id): JsonResponse
    {
        /** @var \App\Entity\Users $thisuser */
        $thisuser = $this->getUser();

        if (!$thisuser) {
            return $this->json(['type' => 'error', 'message' => 'You are not logged in'], Response::HTTP_UNAUTHORIZED);
        }

        $thisuserId = $thisuser->getUserId();
        $thisuserRole = $thisuser->getRole()->getName();
        $thisuserStatus = $thisuser->getStatus();

        if ($thisuserStatus !== 'active') {
            $this->globalService->forceSignOut($entityManager, $thisuserId);
            return $this->json(['type' => 'error', 'message' => 'You are not active'], Response::HTTP_UNAUTHORIZED);
        }

        if (!in_array($thisuserRole, ["ROLE_ADMIN", "ROLE_COACH"])) {
            return $this->json(['type' => 'error', 'message' => 'You are not an administrator or a coach'], Response::HTTP_BAD_REQUEST);
        }

        $category = $entityManager->find(Categories::class, $id);

        if (!$category) {
            return $this->json(['type' => 'error', 'message' => 'Category not found'], Response::HTTP_BAD_REQUEST);
        }

        $categoryData = [];

        $categoryData[] = [
            'id' => $category->getCategoryId(),
            'name' => $category->getName(),
            "active" => $category->getActive()
        ];

        return $this->json($categoryData, Response::HTTP_OK);
    }

    #[Route('/createCategory', name: 'api_createCategory', methods: ['POST'])]
    public function createCategory(EntityManagerInterface $entityManager, Request $request): JsonResponse
    {
        try {
            /** @var \App\Entity\Users $thisuser */
            $thisuser = $this->getUser();

            if (!$thisuser) {
                return $this->json(['type' => 'error', 'message' => 'You are not logged in'], Response::HTTP_UNAUTHORIZED);
            }

            $thisuserId = $thisuser->getUserId();
            $thisuserRole = $thisuser->getRole()->getName();
            $thisuserStatus = $thisuser->getStatus();

            if ($thisuserStatus !== 'active') {
                $this->globalService->forceSignOut($entityManager, $thisuserId);
                return $this->json(['type' => 'error', 'message' => 'You are not active'], Response::HTTP_UNAUTHORIZED);
            }

            if (!in_array($thisuserRole, ["ROLE_ADMIN", "ROLE_COACH"])) {
                return $this->json(['type' => 'error', 'message' => 'You are not an administrator or a coach'], Response::HTTP_BAD_REQUEST);
            }

            $data = json_decode($request->getContent(), true);

            $name = $this->globalService->validate(strtoupper($data['name'] ?? ""));

            $categorie_regex = "/^[A-Z]{4,50}$/";

            if ($name === "") {
                return $this->json(['type' => 'error', 'message' => 'Invalid data'], Response::HTTP_BAD_REQUEST);
            }

            if (!preg_match($categorie_regex, $name)) {
                return $this->json(['type' => 'error', 'message' => 'Invalid name format'], Response::HTTP_BAD_REQUEST);
            }

            if ($this->categoryService->categoryExisting($name, $entityManager)) {
                return $this->json(['type' => 'error', 'message' => 'Category already exists', Response::HTTP_BAD_REQUEST]);
            }

            $newCategory = new Categories();

            $newCategory->setName($name);
            $newCategory->setActive(true);

            $entityManager->persist($newCategory);
            $entityManager->flush();

            return $this->json(['type' => 'success', 'message' => 'Categorie successfully created'], Response::HTTP_CREATED);
        } catch (\Exception $e) {
            return $this->json(['type' => 'error', 'message' => 'An error occurred while creating the category'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    #[Route('/deleteCategory/{id<\d+>}', name: 'api_deleteCategory', methods: ['DELETE'])]
    public function deleteCategory(EntityManagerInterface $entityManager, int $id): JsonResponse
    {
        try {
            /** @var \App\Entity\Users $thisuser */
            $thisuser = $this->getUser();

            if (!$thisuser) {
                return $this->json(['type' => 'error', 'message' => 'You are not logged in'], Response::HTTP_UNAUTHORIZED);
            }

            $thisuserId = $thisuser->getUserId();
            $thisuserRole = $thisuser->getRole()->getName();
            $thisuserStatus = $thisuser->getStatus();

            if ($thisuserStatus !== 'active') {
                $this->globalService->forceSignOut($entityManager, $thisuserId);
                return $this->json(['type' => 'error', 'message' => 'You are not active'], Response::HTTP_UNAUTHORIZED);
            }

            if (!in_array($thisuserRole, ["ROLE_ADMIN", "ROLE_COACH"])) {
                return $this->json(['type' => 'error', 'message' => 'You are not an administrator or a coach'], Response::HTTP_BAD_REQUEST);
            }

            $categorie = $entityManager->find(Categories::class, $id);

            if (!$categorie) {
                return $this->json(['type' => 'error', 'message' => 'The categorie does not exist'], Response::HTTP_BAD_REQUEST);
            }

            $categorie->setActive(false);
            $entityManager->flush();

            return $this->json(['type' => 'success', 'message' => 'Categorie successfully deleted'], Response::HTTP_CREATED);
        } catch (\Exception $e) {
            return $this->json(['type' => 'error', 'message' => 'An error occurred while deleting the category'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    #[Route('/activeCategory/{id<\d+>}', name: 'api_activeCategory', methods: ['PUT'])]
    public function activeCategory(EntityManagerInterface $entityManager, int $id): JsonResponse
    {
        try {
            /** @var \App\Entity\Users $thisuser */
            $thisuser = $this->getUser();

            if (!$thisuser) {
                return $this->json(['type' => 'error', 'message' => 'You are not logged in'], Response::HTTP_UNAUTHORIZED);
            }

            $thisuserId = $thisuser->getUserId();
            $thisuserRole = $thisuser->getRole()->getName();
            $thisuserStatus = $thisuser->getStatus();

            if ($thisuserStatus !== 'active') {
                $this->globalService->forceSignOut($entityManager, $thisuserId);
                return $this->json(['type' => 'error', 'message' => 'You are not active'], Response::HTTP_UNAUTHORIZED);
            }

            if (!in_array($thisuserRole, ["ROLE_ADMIN", "ROLE_COACH"])) {
                return $this->json(['type' => 'error', 'message' => 'You are not an administrator or a coach'], Response::HTTP_BAD_REQUEST);
            }

            $categorie = $entityManager->find(Categories::class, $id);

            if (!$categorie) {
                return $this->json(['type' => 'error', 'message' => 'The categorie does not exist'], Response::HTTP_BAD_REQUEST);
            }

            $categorie->setActive(true);
            $entityManager->flush();

            return $this->json(['type' => 'success', 'message' => 'Categorie successfully activated'], Response::HTTP_CREATED);
        } catch (\Exception $e) {
            return $this->json(['type' => 'error', 'message' => 'An error occurred while activating the category'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    #[Route('/modifyCategory/{id<\d+>}', name: 'api_modifyCategory', methods: ['GET', 'PUT'])]
    public function modifyCategory(EntityManagerInterface $entityManager, Request $request, int $id): JsonResponse
    {
        /** @var \App\Entity\Users $thisuser */
        $thisuser = $this->getUser();

        if (!$thisuser) {
            return $this->json(['type' => 'error', 'message' => 'You are not logged in'], Response::HTTP_UNAUTHORIZED);
        }

        $thisuserId = $thisuser->getUserId();
        $thisuserRole = $thisuser->getRole()->getName();
        $thisuserStatus = $thisuser->getStatus();

        if ($thisuserStatus !== 'active') {
            $this->globalService->forceSignOut($entityManager, $thisuserId);
            return $this->json(['type' => 'error', 'message' => 'You are not active'], Response::HTTP_UNAUTHORIZED);
        }

        if (!in_array($thisuserRole, ["ROLE_ADMIN", "ROLE_COACH"])) {
            return $this->json(['type' => 'error', 'message' => 'You are not an administrator or a coach'], Response::HTTP_BAD_REQUEST);
        }

        $category = $entityManager->find(Categories::class, $id);

        if (!$category) {
            return $this->json(['type' => 'warning', 'message' => 'No category found'], Response::HTTP_BAD_REQUEST);
        }

        if ($request->isMethod('GET')) {
            $categoryData = [
                'id' => $category->getCategoryId(),
                'name' => $category->getName(),
                "active" => $category->getActive()
            ];

            return $this->json($categoryData, Response::HTTP_OK);
        }

        if ($request->isMethod('PUT')) {
            try {
                $data = json_decode($request->getContent(), true);

                $name = $this->globalService->validate(strtoupper($data['name'] ?? ""));
                $active = array_key_exists('active', $data)
                    ? filter_var($data['active'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE)
                    : null;

                $categorie_regex = "/^[A-Z]{4,50}$/";

                if ($name === "" || $active === null) {
                    return $this->json(['type' => 'error', 'message' => 'Invalid data'], Response::HTTP_BAD_REQUEST);
                }

                if ($this->categoryService->categoryExisting2($id, $name, $entityManager)) {
                    return $this->json(['type' => 'error', 'message' => 'Category already exists', Response::HTTP_BAD_REQUEST]);
                }

                if (!preg_match($categorie_regex, $name)) {
                    return $this->json(['type' => 'error', 'message' => 'Invalid name format'], Response::HTTP_BAD_REQUEST);
                }

                $category->setName($name);
                if ($active !== null) {
                    $category->setActive($active);
                }

                $entityManager->flush();

                return $this->json(['type' => 'success', 'message' => 'Category successfully updated'], Response::HTTP_CREATED);
            } catch (\Exception $e) {
                return $this->json(['type' => 'error', 'message' => 'An error occurred while modifying the category'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }

        return $this->json(['type' => 'error', 'message' => 'Method not allowed'], Response::HTTP_METHOD_NOT_ALLOWED);
    }
}
