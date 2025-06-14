<?php

namespace App\Controller;

use App\Entity\Roles;
use App\Service\GlobalService;
use App\Service\RoleService;
use App\Service\UserService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\HttpFoundation\Response;
use OpenApi\Attributes as OA;

#[Route('/api/roles')]
class RolesController extends AbstractController
{
    public function __construct(
        private UserService $userService,
        private GlobalService $globalService,
        private RoleService $roleService,
    ) {}

    //!CON JS AL DEVOLVER UN JSON CON EL active SE PUEDE FILTAR EN EL FRONT POR active SIN NECESIDAD DE CREAR UN METODO DE seeAllActiveRoles Y QUITARNIOS EL RECARGAR LA PÁGINA PUDIENDIO HACER UN Switches PARA ALTERNAR ENTRE ACTIVOS O TODOS

    //!COMO RolesController SOLO LO VE EL ADMIN NO HAY NECESIDAD DE CREAR UN ENDPOINT PARA CER UN SOLO ROL, AL CARGAR LA PÁGINA NOS TRAEMOS TODOS LOS ROLES, SI QUIERES VER UNO EN ESPECIDICO PARA MODIFICARLO SOLO HAS DE BUSCARLO CON EL ID CON JS EN EL JSON, NOS QUITAMOS TIEMPOS DE CARGA
    #[OA\Get(
        path: '/api/users/seeAllRoles',
        summary: 'Get All Roles',
        description: 'Retrieve all available roles in the system. Only accessible by administrators.',
        tags: ['Roles']
    )]
    #[OA\Response(
        response: 200,
        description: 'Successful retrieval of roles list',
        content: new OA\JsonContent(
            type: 'array',
            items: new OA\Items(
                type: 'object',
                properties: [
                    new OA\Property(property: 'id_role', type: 'integer', example: 1),
                    new OA\Property(property: 'name', type: 'string', example: 'ROLE_ADMIN'),
                    new OA\Property(property: 'description', type: 'string', example: 'Administrator role')
                ]
            )
        )
    )]
    #[OA\Response(
        response: 400,
        description: 'Bad Request - No roles found or insufficient permissions',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', enum: ['warning', 'error']),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'No roles found',
                        'You are not an administrator'
                    ]
                )
            ]
        )
    )]
    #[OA\Response(
        response: 401,
        description: 'Unauthorized - User not logged in or not active',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'You are not logged in',
                        'You are not active'
                    ]
                )
            ]
        )
    )]
    #[Route('/seeAllRoles', name: 'api_seeAllRoles', methods: ['GET'])]
    public function seeAllRoles(EntityManagerInterface $entityManager): JsonResponse
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

        if ($thisuserRole !== 'ROLE_ADMIN') {
            return $this->json(['type' => 'error', 'message' => 'You are not an administrator'], Response::HTTP_BAD_REQUEST);
        }

        $roles = $entityManager->getRepository(Roles::class)->findAll();

        if (!$roles) {
            return $this->json(['type' => 'warning', 'message' => 'No roles found'], Response::HTTP_OK);
        }

        $rolesData = [];

        foreach ($roles as $data) {
            $rolesData[] = [
                'id' => $data->getRoleId(),
                'name' => $data->getName(),
                "active" => $data->getActive()
            ];
        }

        return $this->json($rolesData, Response::HTTP_OK);
    }

    //!SE CREA POS SI SE QUIERE CONSUMIR COMO API, NO SE USA EN EL FRONT
    #[OA\Get(
        path: '/api/users/seeOneRole/{id}',
        summary: 'Get Role by ID',
        description: 'Retrieve detailed information about a specific role by its ID. Only accessible by administrators.',
        tags: ['Roles', 'Administration']
    )]
    #[OA\Parameter(
        name: 'id',
        description: 'Role unique identifier',
        in: 'path',
        required: true,
        schema: new OA\Schema(type: 'integer', minimum: 1),
        example: 1
    )]
    #[OA\Response(
        response: 200,
        description: 'Successful retrieval of role information',
        content: new OA\JsonContent(
            type: 'array',
            items: new OA\Items(
                type: 'object',
                properties: [
                    new OA\Property(property: 'id', type: 'integer', description: 'Role unique identifier', example: 1),
                    new OA\Property(property: 'name', type: 'string', description: 'Role name', example: 'ROLE_ADMIN'),
                    new OA\Property(property: 'active', type: 'boolean', description: 'Role active status', example: true)
                ]
            )
        )
    )]
    #[OA\Response(
        response: 400,
        description: 'Bad Request - Role not found or user is not an administrator',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'No role found',
                        'You are not an administrator'
                    ]
                )
            ]
        )
    )]
    #[OA\Response(
        response: 401,
        description: 'Unauthorized - User not logged in or not active',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'You are not logged in',
                        'You are not active'
                    ]
                )
            ]
        )
    )]
    #[Route('/seeOneRole/{id<\d+>}', name: 'seeOneRole', methods: ['GET'])]
    public function seeOneRole(EntityManagerInterface $entityManager, int $id): JsonResponse
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

        if ($thisuserRole !== 'ROLE_ADMIN') {
            return $this->json(['type' => 'error', 'message' => 'You are not an administrator'], Response::HTTP_BAD_REQUEST);
        }

        $role = $entityManager->find(Roles::class, $id);

        if (!$role) {
            return $this->json(['type' => 'error', 'message' => 'No role found'], Response::HTTP_BAD_REQUEST);
        }

        $roleData = [];

        $roleData[] = [
            'id' => $role->getRoleId(),
            'name' => $role->getName(),
            "active" => $role->getActive()
        ];

        return $this->json($roleData, Response::HTTP_OK);
    }

    #[OA\Post(
        path: '/api/users/createRole',
        summary: 'Create New Role',
        description: 'Create a new role in the system. Only accessible by administrators.',
        tags: ['Roles', 'Administration']
    )]
    #[OA\RequestBody(
        description: 'Role creation data',
        required: true,
        content: new OA\JsonContent(
            required: ['name'],
            properties: [
                new OA\Property(
                    property: 'name',
                    type: 'string',
                    description: 'Role name (must follow format ROLE_[A-Z]{4,50})',
                    pattern: '^ROLE_[A-Z]{4,50}$',
                    example: 'ROLE_MODERATOR'
                )
            ]
        )
    )]
    #[OA\Response(
        response: 201,
        description: 'Role created successfully',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'success'),
                new OA\Property(property: 'message', type: 'string', example: 'Role successfully created')
            ]
        )
    )]
    #[OA\Response(
        response: 400,
        description: 'Bad Request - Invalid data, format, role already exists, or user is not an administrator',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'Invalid data',
                        'Invalid name format',
                        'Role already exists',
                        'You are not an administrator'
                    ]
                )
            ]
        )
    )]
    #[OA\Response(
        response: 401,
        description: 'Unauthorized - User not logged in or not active',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'You are not logged in',
                        'You are not active'
                    ]
                )
            ]
        )
    )]
    #[OA\Response(
        response: 500,
        description: 'Internal Server Error',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(property: 'message', type: 'string', example: 'An error occurred while creating the role')
            ]
        )
    )]
    #[Route('/createRole', name: 'api_createRole', methods: ['POST'])]
    public function createRole(EntityManagerInterface $entityManager, Request $request): JsonResponse
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

            if ($thisuserRole !== 'ROLE_ADMIN') {
                return $this->json(['type' => 'error', 'message' => 'You are not an administrator'], Response::HTTP_BAD_REQUEST);
            }

            $data = json_decode($request->getContent(), true);

            $name = $this->globalService->validate(strtoupper($data['name'] ?? ""));

            $role_regex = "/^ROLE_[A-Z]{4,50}$/";

            if ($name === "") {
                return $this->json(['type' => 'error', 'message' => 'Invalid data'], Response::HTTP_BAD_REQUEST);
            }

            if (!preg_match($role_regex, $name)) {
                return $this->json(['type' => 'error', 'message' => 'Invalid name format'], Response::HTTP_BAD_REQUEST);
            }

            if ($this->roleService->roleExisting($name, $entityManager)) {
                return $this->json(['type' => 'error', 'message' => 'Role already exists', Response::HTTP_BAD_REQUEST]);
            }

            $newRole = new Roles();

            $newRole->setName($name);
            $newRole->setActive(true);

            $entityManager->persist($newRole);
            $entityManager->flush();

            return $this->json(['type' => 'success', 'message' => 'Role successfully created'], Response::HTTP_CREATED);
        } catch (\Exception $e) {
            return $this->json(['type' => 'error', 'message' => 'An error occurred while creating the role'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    #[OA\Delete(
        path: '/api/users/deleteRole/{id}',
        summary: 'Delete Role',
        description: 'Delete (deactivate) an existing role in the system. Only accessible by administrators.',
        tags: ['Roles', 'Administration']
    )]
    #[OA\Parameter(
        name: 'id',
        description: 'Role ID to delete',
        in: 'path',
        required: true,
        schema: new OA\Schema(
            type: 'integer',
            format: 'int64',
            minimum: 1,
            example: 1
        )
    )]
    #[OA\Response(
        response: 201,
        description: 'Role deleted successfully',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'success'),
                new OA\Property(property: 'message', type: 'string', example: 'Role successfully deleted')
            ]
        )
    )]
    #[OA\Response(
        response: 400,
        description: 'Bad Request - Role does not exist or user is not an administrator',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'The role does not exist',
                        'You are not an administrator'
                    ]
                )
            ]
        )
    )]
    #[OA\Response(
        response: 401,
        description: 'Unauthorized - User not logged in or not active',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'You are not logged in',
                        'You are not active'
                    ]
                )
            ]
        )
    )]
    #[OA\Response(
        response: 500,
        description: 'Internal Server Error',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(property: 'message', type: 'string', example: 'An error occurred while deleting the role')
            ]
        )
    )]
    #[Route('/deleteRole/{id<\d+>}', name: 'api_deleteRole', methods: ['DELETE'])]
    public function deleteRole(EntityManagerInterface $entityManager, int $id): JsonResponse
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

            if ($thisuserRole !== 'ROLE_ADMIN') {
                return $this->json(['type' => 'error', 'message' => 'You are not an administrator'], Response::HTTP_BAD_REQUEST);
            }

            $role = $this->roleService->roleExisting($id, $entityManager);

            if (!$role) {
                return $this->json(['type' => 'error', 'message' => 'The role does not exist'], Response::HTTP_BAD_REQUEST);
            }

            $role->setActive(false);
            $entityManager->flush();

            return $this->json(['type' => 'success', 'message' => 'Role successfully deleted'], Response::HTTP_CREATED);
        } catch (\Exception $e) {
            return $this->json(['type' => 'error', 'message' => 'An error occurred while deleting the role'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    #[OA\Put(
        path: '/api/users/activeRole/{id}',
        summary: 'Activate Role',
        description: 'Activate an existing role in the system. Only accessible by administrators.',
        tags: ['Roles', 'Administration']
    )]
    #[OA\Parameter(
        name: 'id',
        description: 'Role ID to activate',
        in: 'path',
        required: true,
        schema: new OA\Schema(
            type: 'integer',
            format: 'int64',
            minimum: 1,
            example: 1
        )
    )]
    #[OA\Response(
        response: 201,
        description: 'Role activated successfully',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'success'),
                new OA\Property(property: 'message', type: 'string', example: 'Role successfully activated')
            ]
        )
    )]
    #[OA\Response(
        response: 400,
        description: 'Bad Request - Role does not exist or user is not an administrator',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'The role does not exist',
                        'You are not an administrator'
                    ]
                )
            ]
        )
    )]
    #[OA\Response(
        response: 401,
        description: 'Unauthorized - User not logged in or not active',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'You are not logged in',
                        'You are not active'
                    ]
                )
            ]
        )
    )]
    #[OA\Response(
        response: 500,
        description: 'Internal Server Error',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(property: 'message', type: 'string', example: 'An error occurred while activating the role')
            ]
        )
    )]
    #[Route('/activeRole/{id<\d+>}', name: 'api_activeRole', methods: ['PUT'])]
    public function activeRole(EntityManagerInterface $entityManager, int $id): JsonResponse
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

            if ($thisuserRole !== 'ROLE_ADMIN') {
                return $this->json(['type' => 'error', 'message' => 'You are not an administrator'], Response::HTTP_BAD_REQUEST);
            }

            $role = $this->roleService->roleExisting($id, $entityManager);

            if (!$role) {
                return $this->json(['type' => 'error', 'message' => 'The role does not exist'], Response::HTTP_BAD_REQUEST);
            }

            $role->setActive(true);
            $entityManager->flush();

            return $this->json(['type' => 'success', 'message' => 'Role successfully activated'], Response::HTTP_CREATED);
        } catch (\Exception $e) {
            return $this->json(['type' => 'error', 'message' => 'An error occurred while activating the role'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    #[OA\Get(
        path: '/api/users/modifyRole/{id}',
        summary: 'Get Role Details',
        description: 'Retrieve details of a specific role by ID. Only accessible by administrators.',
        tags: ['Roles', 'Administration']
    )]
    #[OA\Parameter(
        name: 'id',
        description: 'Role ID to retrieve',
        in: 'path',
        required: true,
        schema: new OA\Schema(
            type: 'integer',
            format: 'int64',
            minimum: 1,
            example: 1
        )
    )]
    #[OA\Response(
        response: 200,
        description: 'Role details retrieved successfully',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'id', type: 'integer', example: 1),
                new OA\Property(property: 'name', type: 'string', example: 'ROLE_MODERATOR'),
                new OA\Property(property: 'active', type: 'boolean', example: true)
            ]
        )
    )]
    #[OA\Response(
        response: 400,
        description: 'Bad Request - Role not found or user is not an administrator',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'warning'),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'No role found',
                        'You are not an administrator'
                    ]
                )
            ]
        )
    )]
    #[OA\Response(
        response: 401,
        description: 'Unauthorized - User not logged in or not active',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'You are not logged in',
                        'You are not active'
                    ]
                )
            ]
        )
    )]
    #[OA\Put(
        path: '/api/users/modifyRole/{id}',
        summary: 'Modify Role',
        description: 'Update an existing role in the system. Administrator role cannot be modified. Only accessible by administrators.',
        tags: ['Roles', 'Administration']
    )]
    #[OA\Parameter(
        name: 'id',
        description: 'Role ID to modify',
        in: 'path',
        required: true,
        schema: new OA\Schema(
            type: 'integer',
            format: 'int64',
            minimum: 1,
            example: 1
        )
    )]
    #[OA\RequestBody(
        description: 'Role modification data',
        required: true,
        content: new OA\JsonContent(
            required: ['name', 'active'],
            properties: [
                new OA\Property(
                    property: 'name',
                    type: 'string',
                    description: 'Role name (must follow format ROLE_[A-Z]{4,50})',
                    pattern: '^ROLE_[A-Z]{4,50}$',
                    example: 'ROLE_MODERATOR'
                ),
                new OA\Property(
                    property: 'active',
                    type: 'boolean',
                    description: 'Role active status',
                    example: true
                )
            ]
        )
    )]
    #[OA\Response(
        response: 201,
        description: 'Role modified successfully',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'success'),
                new OA\Property(property: 'message', type: 'string', example: 'Exercise successfully updated')
            ]
        )
    )]
    #[OA\Response(
        response: 400,
        description: 'Bad Request - Invalid data, format, role already exists, admin role modification, or user is not an administrator',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'No role found',
                        'Invalid data',
                        'The administrator role cannot be changed',
                        'Role already exists',
                        'Invalid name format',
                        'You are not an administrator'
                    ]
                )
            ]
        )
    )]
    #[OA\Response(
        response: 401,
        description: 'Unauthorized - User not logged in or not active',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'You are not logged in',
                        'You are not active'
                    ]
                )
            ]
        )
    )]
    #[OA\Response(
        response: 405,
        description: 'Method Not Allowed',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(property: 'message', type: 'string', example: 'Method not allowed')
            ]
        )
    )]
    #[OA\Response(
        response: 500,
        description: 'Internal Server Error',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(property: 'message', type: 'string', example: 'An error occurred while modifying the role')
            ]
        )
    )]
    #[Route('/modifyRole/{id<\d+>}', name: 'api_modifyRole', methods: ['GET', 'PUT'])]
    public function modifyRole(EntityManagerInterface $entityManager, Request $request, int $id): JsonResponse
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

        if ($thisuserRole !== 'ROLE_ADMIN') {
            return $this->json(['type' => 'error', 'message' => 'You are not an administrator'], Response::HTTP_BAD_REQUEST);
        }

        $roles = $entityManager->find(Roles::class, $id);

        if (!$roles) {
            return $this->json(['type' => 'warning', 'message' => 'No role found'], Response::HTTP_BAD_REQUEST);
        }

        if ($request->isMethod('GET')) {
            $rolesData = [
                'id' => $roles->getRoleId(),
                'name' => $roles->getName(),
                "active" => $roles->getActive()
            ];

            return $this->json($rolesData, Response::HTTP_OK);
        }

        if ($request->isMethod('PUT')) {
            try {
                $data = json_decode($request->getContent(), true);

                $name = $this->globalService->validate(strtoupper($data['name'] ?? ""));
                $active = array_key_exists('active', $data)
                    ? filter_var($data['active'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE)
                    : null;

                $role_regex = "/^ROLE_[A-Z]{4,50}$/";

                if ($name === "" || $active === null) {
                    return $this->json(['type' => 'error', 'message' => 'Invalid data'], Response::HTTP_BAD_REQUEST);
                }

                if ($roles->getName() === "ROLE_ADMIN") {
                    return $this->json(['type' => 'error', 'message' => 'The administrator role cannot be changed'], Response::HTTP_BAD_REQUEST);
                }

                if ($this->roleService->roleExisting2($id, $name, $entityManager)) {
                    return $this->json(['type' => 'error', 'message' => 'Role already exists', Response::HTTP_BAD_REQUEST]);
                }

                if (!preg_match($role_regex, $name)) {
                    return $this->json(['type' => 'error', 'message' => 'Invalid name format'], Response::HTTP_BAD_REQUEST);
                }

                $roles->setName($name);
                if ($active !== null) {
                    $roles->setActive($active);
                }

                $entityManager->flush();

                return $this->json(['type' => 'success', 'message' => 'Exercise successfully updated'], Response::HTTP_CREATED);
            } catch (\Exception $e) {
                return $this->json(['type' => 'error', 'message' => 'An error occurred while modifying the role'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }

        return $this->json(['type' => 'error', 'message' => 'Method not allowed'], Response::HTTP_METHOD_NOT_ALLOWED);
    }
}
