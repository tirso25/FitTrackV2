<?php

namespace App\Controller;

use App\Entity\Roles;
use App\Entity\Users;
use App\Service\CoachService;
use App\Service\FavoritesExercisesService;
use App\Service\FavouritesCoachsService;
use App\Service\GlobalService;
use App\Service\LikesCoachsService;
use App\Service\RoleService;
use App\Service\UserService;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Mailer\MailerInterface;
use Symfony\Component\Routing\Attribute\Route;
use Symfony\Component\Mime\Email;
use Lexik\Bundle\JWTAuthenticationBundle\Services\JWTTokenManagerInterface;
use Lexik\Bundle\JWTAuthenticationBundle\Encoder\JWTEncoderInterface;
use OpenApi\Attributes as OA;

#[Route('/api/users')]
class UsersController extends AbstractController
{
    public function __construct(
        private UserService $userService,
        private GlobalService $globalService,
        private FavoritesExercisesService $favoriteExercisesService,
        private RoleService $roleService,
        private FavouritesCoachsService $favouritesCoachsService,
        private CoachService $coachService,
        private LikesCoachsService $likesCoachsService
    ) {}

    //!CON JS AL DEVOLVER UN JSON CON EL active SE PUEDE FILTAR EN EL FRONT POR active SIN NECESIDAD DE CREAR UN METODO DE seeAllActiveUsers Y QUITARNIOS EL RECARGAR LA PÁGINA PUDIENDIO HACER UN Switches PARA ALTERNAR ENTRE ACTIVOS O TODOS
    #[OA\Get(
        path: '/api/users/seeAllUsers',
        summary: 'Get All Users',
        description: 'Retrieve a list of all users in the system (Admin only)',
        tags: ['Users', 'Administration']
    )]
    #[OA\Response(
        response: 200,
        description: 'Successful retrieval of users list',
        content: new OA\JsonContent(
            type: 'array',
            items: new OA\Items(
                type: 'object',
                properties: [
                    new OA\Property(property: 'id_usr', type: 'integer', example: 1),
                    new OA\Property(property: 'email', type: 'string', example: 'user@example.com'),
                    new OA\Property(property: 'username', type: 'string', example: 'username123'),
                    new OA\Property(property: 'description', type: 'string', example: 'User description'),
                    new OA\Property(property: 'role', type: 'string', example: 'ROLE_USER'),
                    new OA\Property(property: 'status', type: 'string', example: 'active'),
                    new OA\Property(property: 'public', type: 'boolean', example: true),
                    new OA\Property(property: 'date_union', type: 'string', format: 'date-time')
                ]
            )
        )
    )]
    #[OA\Response(
        response: 400,
        description: 'Bad Request - No users found or insufficient permissions',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', enum: ['warning', 'error']),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'No users found',
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
    #[Route('/seeAllUsers', name: 'api_seeAllUsers', methods: ['GET'])]
    public function seeAllUsers(EntityManagerInterface $entityManager): JsonResponse
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

        $users = $this->userService->seeAllUsers($entityManager);

        if (!$users) {
            return $this->json(['type' => 'warning', 'message' => 'No users found'], Response::HTTP_BAD_REQUEST);
        }

        $data = [];

        foreach ($users as $user) {
            $data[] = [
                'id_usr' => $user->getUserId(),
                'email' => $user->getEmail(),
                'username' => $user->getDisplayUsername(),
                'description' => $user->getDescription(),
                'role' => $user->getRole()->getName(),
                'status' => $user->getStatus(),
                'public' => $user->getPublic(),
                'date_union' => $user->getDateUnion()
            ];
        }

        return $this->json($data, Response::HTTP_OK);
    }

    #[OA\Get(
        path: '/api/users/seeOneUser/{id}',
        summary: 'Get Single User',
        description: 'Retrieve detailed information about a specific user by ID. Response varies based on user role (Coach vs User)',
        tags: ['Users']
    )]
    #[OA\Parameter(
        name: 'id',
        description: 'User ID to retrieve',
        in: 'path',
        required: true,
        schema: new OA\Schema(type: 'integer', minimum: 1),
        example: 1
    )]
    #[OA\Response(
        response: 200,
        description: 'Successful retrieval of user information',
        content: new OA\JsonContent(
            type: 'array',
            items: new OA\Items(
                type: 'object',
                properties: [
                    new OA\Property(property: 'id_usr', type: 'integer', example: 1),
                    new OA\Property(property: 'email', type: 'string', example: 'user@example.com'),
                    new OA\Property(property: 'username', type: 'string', example: 'username123'),
                    new OA\Property(property: 'description', type: 'string', example: 'User description'),
                    new OA\Property(property: 'date_union', type: 'string', format: 'date-time'),
                    new OA\Property(
                        property: 'exercises',
                        type: 'array',
                        description: 'Present when user is a coach or current user is a coach',
                        items: new OA\Items(
                            type: 'object',
                            properties: [
                                new OA\Property(property: 'exercise_id', type: 'integer', example: 1),
                                new OA\Property(property: 'exercise_name', type: 'string', example: 'Push ups'),
                                new OA\Property(property: 'exercise_description', type: 'string', example: 'Basic push up exercise'),
                                new OA\Property(property: 'exercise_category', type: 'string', example: 'Strength')
                            ]
                        )
                    ),
                    new OA\Property(
                        property: 'exercisesFavorites',
                        type: 'array',
                        description: 'Present when user is not a coach and current user is not a coach',
                        items: new OA\Items(type: 'object')
                    ),
                    new OA\Property(
                        property: 'coachsFavorites',
                        type: 'array',
                        description: 'Present when user is not a coach and current user is not a coach',
                        items: new OA\Items(type: 'object')
                    )
                ]
            )
        )
    )]
    #[OA\Response(
        response: 400,
        description: 'Bad Request - User not found, pending activation, or restricted access',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', enum: ['error', 'warning']),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'The user does not exist',
                        'The user is pending activation',
                        'The user is not available'
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
    #[Route('/seeOneUser/{id<\d+>}', name: 'api_seeOneUser', methods: ['GET'])]
    public function seeOneUser(EntityManagerInterface $entityManager, int $id)
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

        $user = $entityManager->getRepository(Users::class)->findOneBy(['user_id' => $id]);

        if (!$user) {
            return $this->json(['type' => 'error', 'message' => 'The user does not exist'], Response::HTTP_BAD_REQUEST);
        }

        if ($user->getStatus() === "pending") {
            return $this->json(['type' => 'error', 'message' => 'The user is pending activation'], Response::HTTP_BAD_REQUEST);
        }

        if ($user->getRole()->getName() === "ROLE_ROOT" || $user->getRole()->getName() === "ROLE_ADMIN") {
            return $this->json(['type' => 'warning', 'message' => 'The user is not available'], Response::HTTP_BAD_REQUEST);
        }

        $data = [];

        $exercisesFavorites = $this->favoriteExercisesService->getFavouriteExercisesByUserId($id, $entityManager);
        $coachsFavorites = $this->favouritesCoachsService->getFavouriteCoachsByUserId($id, $entityManager);

        if ($thisuserRole === "ROLE_COACH" || $user->getRole()->getName() === "ROLE_COACH") {
            $coachsExercises = $this->coachService->seeAllExercisesByCoach($entityManager, $id);
            $likes = $this->likesCoachsService->getCoachsLikes($entityManager, $id);

            $exerciseList = [];

            foreach ($coachsExercises as $exercise) {
                $likes = $likes = $exercise->getExerciseLikes()?->getLikes();
                $exerciseList[] = [
                    'exercise_id' => $exercise->getExerciseId(),
                    'exercise_name' => $exercise->getName(),
                    'exercise_description' => $exercise->getDescription(),
                    'exercise_category' => $exercise->getCategory()->getName(),
                    'likes' => $likes
                ];
            }

            $data[] = [
                'id_usr' => $user->getUserId(),
                'email' => $user->getEmail(),
                'username' => $user->getDisplayUsername(),
                'description' => $user->getDescription(),
                'date_union' => $user->getDateUnion(),
                'likes' =>  $likes,
                'exercises' => $exerciseList,
            ];
        } else {
            $data[] = [
                'id_usr' => $user->getUserId(),
                'email' => $user->getEmail(),
                'username' => $user->getDisplayUsername(),
                'description' => $user->getDescription(),
                'date_union' => $user->getDateUnion(),
                'exercisesFavorites' => $exercisesFavorites,
                'coachsFavorites' => $coachsFavorites
            ];
        }

        return $this->json($data, Response::HTTP_OK);
    }

    #[OA\Post(
        path: '/api/users/signUp',
        summary: 'User Registration',
        description: 'Register a new user account with email, username and password',
        tags: ['Users', 'Authentication']
    )]
    #[OA\RequestBody(
        description: 'User registration data',
        required: true,
        content: new OA\JsonContent(
            required: ['email', 'username', 'password', 'repeatPassword'],
            properties: [
                new OA\Property(
                    property: 'email',
                    type: 'string',
                    format: 'email',
                    description: 'Valid email address (max 255 chars)',
                    example: 'user@example.com'
                ),
                new OA\Property(
                    property: 'username',
                    type: 'string',
                    description: 'Username (5-20 chars, lowercase alphanumeric only)',
                    example: 'username123'
                ),
                new OA\Property(
                    property: 'password',
                    type: 'string',
                    description: 'Password (min 5 chars, must contain: uppercase, lowercase, number, special character)',
                    example: 'MyPassword123!'
                ),
                new OA\Property(
                    property: 'repeatPassword',
                    type: 'string',
                    description: 'Password confirmation (must match password)',
                    example: 'MyPassword123!'
                )
            ]
        )
    )]
    #[OA\Response(
        response: 201,
        description: 'User successfully created',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'success'),
                new OA\Property(property: 'message', type: 'string', example: 'User successfully created')
            ]
        )
    )]
    #[OA\Response(
        response: 400,
        description: 'Bad Request - Invalid data, format errors, or user already exists',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'Invalid data',
                        'Invalid email format',
                        'Invalid password format',
                        'Invalid username format',
                        'User already exists',
                        'Passwords dont match'
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
                new OA\Property(property: 'message', type: 'string', example: 'An error occurred while singUp the user')
            ]
        )
    )]
    #[Route('/signUp', name: 'api_signUp', methods: ['POST'])]
    public function signUp(EntityManagerInterface $entityManager, Request $request): JsonResponse
    {
        try {
            $data = json_decode($request->getContent(), true);

            $email = $this->globalService->validate(strtolower($data['email'] ?? ""));
            $username = $this->globalService->validate(strtolower($data['username'] ?? ""));
            $password = $data['password'] ?? "";
            $repeatPassword = $data['repeatPassword'] ?? "";

            $password_regex = "/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_])[A-Za-z\d\W_]{5,}$/";
            $username_regex = "/^[a-z0-9]{5,20}$/";

            if ($email === "" || $username === "" || $password === "" || $repeatPassword === "") {
                return $this->json(['type' => 'error', 'message' => 'Invalid data'], Response::HTTP_BAD_REQUEST);
            }

            if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 255) {
                return $this->json(['type' => 'error', 'message' => 'Invalid email format'], Response::HTTP_BAD_REQUEST);
            }

            if (!preg_match($password_regex, $password) || !preg_match($password_regex, $repeatPassword)) {
                return $this->json(['type' => 'error', 'message' => 'Invalid password format'], Response::HTTP_BAD_REQUEST);
            }

            if (!preg_match($username_regex, $username)) {
                return $this->json(['type' => 'error', 'message' => 'Invalid username format'], Response::HTTP_BAD_REQUEST);
            }

            if ($this->userService->userExisting3($email, $username, $entityManager)) {
                return $this->json(['type' => 'error', 'message' => 'User already exists'], Response::HTTP_BAD_REQUEST);
            }

            if ($password !== $repeatPassword) {
                return $this->json(['type' => 'error', 'message' => 'Passwords dont match'], Response::HTTP_BAD_REQUEST);
            }

            $role = $entityManager->find(Roles::class, 4);

            $newUser = new Users();

            $newUser->setEmail($email);
            $newUser->setUsername($username);
            $newUser->setPassword($this->userService->hashPassword($password));
            $newUser->setRole($role);
            $newUser->setStatus('pending');
            $newUser->setPublic(true);
            $newUser->setDateUnion(new \DateTime());


            $entityManager->persist($newUser);
            $entityManager->flush();

            return $this->json(['type' => 'success', 'message' => 'User successfully created'], Response::HTTP_CREATED);
        } catch (\Exception $e) {
            return $this->json(['type' => 'error', 'message' => 'An error occurred while singUp the user'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    #[OA\Post(
        path: '/api/users/signIn',
        summary: 'User Sign In',
        description: 'Authenticate user with email/username and password',
        tags: ['Users', 'Authentication']
    )]
    #[OA\RequestBody(
        description: 'User login credentials',
        required: true,
        content: new OA\JsonContent(
            required: ['email', 'password', 'rememberme'],
            properties: [
                new OA\Property(
                    property: 'email',
                    type: 'string',
                    description: 'User email or username (4-20 chars if username, valid email if email)',
                    example: 'user@example.com'
                ),
                new OA\Property(
                    property: 'password',
                    type: 'string',
                    description: 'User password (min 5 chars, must contain: uppercase, lowercase, number, special character)',
                    example: 'MyPassword123!'
                ),
                new OA\Property(
                    property: 'rememberme',
                    type: 'boolean',
                    description: 'Remember user session for 30 days',
                    example: true
                )
            ]
        )
    )]
    #[OA\Response(
        response: 200,
        description: 'Successful sign in',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'success'),
                new OA\Property(property: 'message', type: 'string', example: 'Session successfully started'),
                new OA\Property(property: 'token', type: 'string', example: 'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9...'),
                new OA\Property(
                    property: 'userData',
                    type: 'object',
                    properties: [
                        new OA\Property(property: 'this_user_id', type: 'integer', example: 1),
                        new OA\Property(property: 'this_user_email', type: 'string', example: 'user@example.com'),
                        new OA\Property(property: 'this_user_username', type: 'string', example: 'username123'),
                        new OA\Property(property: 'this_user_role_id', type: 'integer', example: 2),
                        new OA\Property(property: 'this_user_role', type: 'string', example: 'User'),
                        new OA\Property(property: 'this_user_date_union', type: 'string', format: 'date-time')
                    ]
                ),
                new OA\Property(property: 'rememberToken', type: 'string', example: 'a1b2c3d4e5f6...', description: 'Only present when rememberme is true')
            ]
        )
    )]
    #[OA\Response(
        response: 400,
        description: 'Bad Request - Invalid data, format, user not found, or user status issues',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', enum: ['error', 'warning']),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'Invalid data',
                        'Invalid email format',
                        'Invalid username format',
                        'Invalid password format',
                        'The user does not exist',
                        'This user is pending activation',
                        'User or password doesnt match'
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
                new OA\Property(property: 'message', type: 'string', example: 'Error interno al hacer signIn: ...')
            ]
        )
    )]
    #[Route('/signIn', name: 'api_signIn', methods: ['POST'])]
    public function signIn(EntityManagerInterface $entityManager, Request $request, JWTTokenManagerInterface $jwtManager, JWTEncoderInterface $jwtEncoder): JsonResponse
    {
        try {
            $data = json_decode($request->getContent(), true);

            $email = $this->globalService->validate(strtolower($data['email'] ?? ""));
            $password = $this->globalService->validate($data['password'] ?? "");
            $rememberme = isset($data['rememberme']) ? filter_var($data['rememberme'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE) : null;

            $password_regex = "/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_])[A-Za-z\d\W_]{5,}$/";
            $username_regex = "/^[a-z0-9]{4,20}$/";

            if ($email === "" || $password === "" || $rememberme === null) {
                return $this->json(['type' => 'error', 'message' => 'Invalid data'], Response::HTTP_BAD_REQUEST);
            }

            if (str_contains($email, '@')) {
                if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 255) {
                    return $this->json(['type' => 'error', 'message' => 'Invalid email format'], Response::HTTP_BAD_REQUEST);
                }
            } else {
                if (!preg_match($username_regex, $email)) {
                    return $this->json(['type' => 'error', 'message' => 'Invalid username format'], Response::HTTP_BAD_REQUEST);
                }
            }

            if (!preg_match($password_regex, $password)) {
                return $this->json(['type' => 'error', 'message' => 'Invalid password format'], Response::HTTP_BAD_REQUEST);
            }

            $user = $this->userService->userExisting($email, $entityManager);

            if (!$user) {
                return $this->json(['type' => 'error', 'message' => 'The user does not exist'], Response::HTTP_BAD_REQUEST);
            }

            $state_user = $user->getStatus();
            $id_user = $user->getUserId();

            switch ($state_user) {
                case "pending":
                    return $this->json(['type' => 'warning', 'message' => 'This user is pending activation'], Response::HTTP_BAD_REQUEST);
                case "deleted":
                    return $this->json(['type' => 'error', 'message' => 'The user does not exist'], Response::HTTP_BAD_REQUEST);
            }

            $hashedPassword = $user->getPassword();
            $passwordVerify = password_verify($password, $hashedPassword) || $password === $hashedPassword;

            if (!$passwordVerify) {
                return $this->json(['type' => 'error', 'message' => 'User or password doesnt match'], Response::HTTP_BAD_REQUEST);
            }

            $rememberToken = null;

            if ($rememberme === true) {
                $payload = [
                    'username' => $user->getUserIdentifier(),
                    'roles' => $user->getRoles(),
                    'exp' => time() + (3600 * 24 * 30),
                ];

                $jwtToken = $jwtEncoder->encode($payload);

                $rememberToken = bin2hex(random_bytes(32));

                $cookieExpire = time() + (3600 * 24 * 30);
                setcookie(
                    "rememberToken",
                    $rememberToken,
                    [
                        'expires' => $cookieExpire,
                        'path' => '/',
                        'secure' => true,
                        'httponly' => true,
                        'samesite' => 'None'
                    ]
                );

                $user->setToken($rememberToken);
            } elseif ($rememberme == false) {
                $jwtToken = $jwtManager->create($user);

                $this->userService->removeToken($entityManager, $id_user);

                if (isset($_COOKIE['rememberToken'])) {
                    setcookie("rememberToken", "", [
                        'expires' => time() - 3600,
                        'path' => '/',
                        'secure' => false,
                        'httponly' => false,
                        'samesite' => 'Strict'
                    ]);

                    unset($_COOKIE['rememberToken']);
                }
            }

            $userData = [
                'this_user_id' => $user->getUserId(),
                'this_user_email' =>  $user->getEmail(),
                'this_user_username' => $user->getDisplayUsername(),
                'this_user_role_id' => $user->getRole()->getRoleId(),
                'this_user_role' => $user->getRole()->getName(),
                'this_user_date_union' => $user->getDateUnion()
            ];

            $entityManager->persist($user);
            $entityManager->flush();

            $response = [
                'type' => 'success',
                'message' => 'Session successfully started',
                'token' => $jwtToken,
                'userData' => $userData
            ];

            if ($rememberme === true && $rememberToken) {
                $response['rememberToken'] = $rememberToken;
            }

            return $this->json($response, Response::HTTP_OK);
        } catch (\Exception $e) {
            return $this->json([
                'type' => 'error',
                'message' => 'Error interno al hacer signIn: ' . $e->getMessage()
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    //!BORRAR EL JWT DEL LOCALSTORAGE
    #[OA\Post(
        path: '/api/users/signOut',
        summary: 'User Sign Out',
        description: 'End user session and remove authentication tokens',
        tags: ['Users', 'Authentication']
    )]
    #[OA\Response(
        response: 200,
        description: 'Successful sign out',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'success'),
                new OA\Property(property: 'message', type: 'string', example: 'Session successfully ended')
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
    #[Route('/signOut', name: 'api_signOut', methods: ['POST'])]
    public function signOut(EntityManagerInterface $entityManager): JsonResponse
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

        $this->globalService->forceSignOut($entityManager, $thisuserId);

        return $this->json(['type' => 'success', 'message' => 'Session successfully ended'], Response::HTTP_OK);
    }

    #[OA\Post(
        path: '/api/users/tokenExisting',
        summary: 'Check Remember Token',
        description: 'Validate remember token from cookies and retrieve user data for auto-login',
        tags: ['Users', 'Authentication']
    )]
    #[OA\Parameter(
        name: 'rememberToken',
        description: 'Remember token stored in HTTP-only cookie',
        in: 'cookie',
        required: false,
        schema: new OA\Schema(type: 'string'),
        example: 'a1b2c3d4e5f6...'
    )]
    #[OA\Response(
        response: 200,
        description: 'Valid token - User data retrieved successfully',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'success'),
                new OA\Property(property: 'message', type: 'string', example: 'Welcome back username123!!!'),
                new OA\Property(
                    property: 'userData',
                    type: 'object',
                    properties: [
                        new OA\Property(property: 'this_user_id', type: 'integer', example: 1),
                        new OA\Property(property: 'this_user_email', type: 'string', example: 'user@example.com'),
                        new OA\Property(property: 'this_user_username', type: 'string', example: 'username123'),
                        new OA\Property(property: 'this_user_role_id', type: 'integer', example: 2),
                        new OA\Property(property: 'this_user_role', type: 'string', example: 'User'),
                        new OA\Property(property: 'this_user_date_union', type: 'string', format: 'date-time')
                    ]
                )
            ]
        )
    )]
    #[OA\Response(
        response: 200,
        description: 'No remember token found',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'info'),
                new OA\Property(property: 'message', type: 'string', example: 'No remember token found')
            ]
        )
    )]
    #[OA\Response(
        response: 401,
        description: 'Unauthorized - Invalid or expired token',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(property: 'message', type: 'string', example: 'Invalid or expired token')
            ]
        )
    )]
    #[OA\Response(
        response: 403,
        description: 'Forbidden - Account not active',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(property: 'message', type: 'string', example: 'Account not active')
            ]
        )
    )]
    #[OA\Response(
        response: 500,
        description: 'Internal Server Error',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(property: 'message', type: 'string', example: 'Error checking token')
            ]
        )
    )]
    #[Route('/tokenExisting', name: 'app_tokenExisting', methods: ['POST'])]
    public function tokenExisting(EntityManagerInterface $entityManager, Request $request): JsonResponse
    {
        try {
            $token = $request->cookies->get('rememberToken');

            if (!$token) {
                return $this->json(['type' => 'info', 'message' => 'No remember token found']);
            }

            $user = $entityManager->getRepository(Users::class)->findOneBy(['token' => $token]);

            if (!$user) {

                setcookie("rememberToken", "", [
                    'expires' => time() - 3600,
                    'path' => '/',
                    'secure' => false,
                    'httponly' => false,
                    'samesite' => 'Strict'
                ]);

                return $this->json([
                    'type' => 'error',
                    'message' => 'Invalid or expired token'
                ], Response::HTTP_UNAUTHORIZED);
            }

            if ($user->getStatus() !== 'active') {
                return $this->json([
                    'type' => 'error',
                    'message' => 'Account not active'
                ], Response::HTTP_FORBIDDEN);
            }

            $username = $user->getDisplayUsername();

            return $this->json([
                'type' => 'success',
                'message' => "Welcome back $username!!!",
                'userData' => [
                    'this_user_id' => $user->getUserId(),
                    'this_user_email' => $user->getEmail(),
                    'this_user_username' => $user->getDisplayUsername(),
                    'this_user_role_id' => $user->getRole()->getRoleId(),
                    'this_user_role' => $user->getRole()->getName(),
                    'this_user_date_union' => $user->getDateUnion()
                ]
            ]);
        } catch (\Exception $e) {
            return $this->json([
                'type' => 'error',
                'message' => 'Error checking token'
            ], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    //!DEPENDIENDO DE LO QUE SE DIGA SE ÙEDE QUITAR PQ YA LO HACE modifyUser
    #[OA\Delete(
        path: '/api/users/deleteUser/{id}',
        summary: 'Delete User',
        description: 'Soft delete a user by setting status to deleted (Admin only)',
        tags: ['Users', 'Administration']
    )]
    #[OA\Parameter(
        name: 'id',
        description: 'User ID to delete',
        in: 'path',
        required: true,
        schema: new OA\Schema(type: 'integer', minimum: 1),
        example: 1
    )]
    #[OA\Response(
        response: 201,
        description: 'User successfully deleted',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'success'),
                new OA\Property(property: 'message', type: 'string', example: 'User successfully deleted')
            ]
        )
    )]
    #[OA\Response(
        response: 400,
        description: 'Bad Request - User not found, insufficient permissions, or cannot delete admin',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'You are not an administrator',
                        'The user does not exist',
                        'Only root users can delete administrators'
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
                new OA\Property(property: 'message', type: 'string', example: 'An error occurred while deleting the user')
            ]
        )
    )]
    #[Route('/deleteUser/{id<\d+>}', name: 'api_deleteUser', methods: ['DELETE'])]
    public function deleteUser(EntityManagerInterface $entityManager, int $id): JsonResponse
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

            $delUser = $entityManager->find(Users::class, $id);
            $roleDelUser = $delUser->getRole()->getName();

            if (!$delUser) {
                return $this->json(['type' => 'error', 'message' => 'The user does not exist'], Response::HTTP_BAD_REQUEST);
            }

            if ($thisuserRole !== 'ROLE_ADMIN' && $roleDelUser === "ROLE_ADMIN") {
                return $this->json(['type' => 'error', 'message' => 'Only root users can delete administrators'], Response::HTTP_BAD_REQUEST);
            }

            $delUser->setStatus('deleted');
            $entityManager->flush();


            return $this->json(['type' => 'success', 'message' => 'User successfully deleted'], Response::HTTP_CREATED);
        } catch (\Exception $e) {
            return $this->json(['type' => 'error', 'message' => 'An error occurred while deleting the user'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    //!DEPENDIENDO DE LO QUE SE DIGA SE ÙEDE QUITAR PQ YA LO HACE modifyUser
    #[OA\Put(
        path: '/api/users/activeUser/{id}',
        summary: 'Activate User',
        description: 'Activate a user by setting their status to active. Only administrators can perform this action.',
        tags: ['Users', 'Administration']
    )]
    #[OA\Parameter(
        name: 'id',
        description: 'User ID to activate',
        in: 'path',
        required: true,
        schema: new OA\Schema(type: 'integer', minimum: 1, example: 1)
    )]
    #[OA\Response(
        response: 201,
        description: 'User successfully activated',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'success'),
                new OA\Property(property: 'message', type: 'string', example: 'User successfully activated')
            ]
        )
    )]
    #[OA\Response(
        response: 400,
        description: 'Bad Request - Permission denied or user not found',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', enum: ['error']),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'You are not an administrator',
                        'The user does not exist'
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
                new OA\Property(property: 'type', type: 'string', enum: ['error']),
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
                new OA\Property(property: 'message', type: 'string', example: 'An error occurred while activating the user')
            ]
        )
    )]
    #[Route('/activeUser/{id<\d+>}', name: 'app_activeUser', methods: ['PUT'])]
    public function activeUser(EntityManagerInterface $entityManager, int $id): JsonResponse
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

            $user = $entityManager->find(Users::class, $id);

            if (!$user) {
                return $this->json(['type' => 'error', 'message' => 'The user does not exist'], Response::HTTP_BAD_REQUEST);
            }

            $user->setStatus('active');

            $entityManager->flush();

            return $this->json(['type' => 'success', 'message' => 'User successfully activated'], Response::HTTP_CREATED);
        } catch (\Exception $e) {
            return $this->json(['type' => 'error', 'message' => 'An error occurred while activating the user'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    #[OA\Get(
        path: '/api/users/modifyUser/{id}',
        summary: 'Get User Data for Modification',
        description: 'Retrieve user data along with available roles and status options for modification. Requires authentication and proper permissions.',
        tags: ['Users', 'Administration']
    )]
    #[OA\Parameter(
        name: 'id',
        description: 'User ID to retrieve data for modification',
        in: 'path',
        required: true,
        schema: new OA\Schema(type: 'integer', minimum: 1, example: 1)
    )]
    #[OA\Response(
        response: 200,
        description: 'User data retrieved successfully',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'id_usr', type: 'integer', example: 1),
                new OA\Property(property: 'username', type: 'string', example: 'username123'),
                new OA\Property(property: 'description', type: 'string', example: 'User description', nullable: true),
                new OA\Property(property: 'public', type: 'boolean', example: true),
                new OA\Property(property: 'status', type: 'string', example: 'active'),
                new OA\Property(property: 'role_id', type: 'integer', example: 2),
                new OA\Property(property: 'role_name', type: 'string', example: 'ROLE_USER'),
                new OA\Property(
                    property: 'roles',
                    type: 'array',
                    items: new OA\Items(
                        type: 'object',
                        properties: [
                            new OA\Property(property: 'id', type: 'integer', example: 1),
                            new OA\Property(property: 'name', type: 'string', example: 'ROLE_ADMIN')
                        ]
                    )
                ),
                new OA\Property(
                    property: 'types_status',
                    type: 'array',
                    items: new OA\Items(type: 'string'),
                    example: ['active', 'deleted']
                )
            ]
        )
    )]
    #[OA\Response(
        response: 401,
        description: 'Unauthorized - User not logged in or not active',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', enum: ['error']),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'You are not logged in',
                        'You are not active',
                        'The user does not exist'
                    ]
                )
            ]
        )
    )]
    #[OA\Response(
        response: 400,
        description: 'Bad Request - Permission denied or invalid user',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', enum: ['error']),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'You cannot modify root users',
                        'Only root users can modify administrators',
                        'Only administrators users can modify coachs',
                        'The user does not exist',
                        'The user does not match'
                    ]
                )
            ]
        )
    )]
    #[OA\Put(
        path: '/api/users/modifyUser/{id}',
        summary: 'Modify User',
        description: 'Update user information including username, password, role, public status, and description. Requires authentication and proper permissions.',
        tags: ['Users', 'Administration']
    )]
    #[OA\Parameter(
        name: 'id',
        description: 'User ID to modify',
        in: 'path',
        required: true,
        schema: new OA\Schema(type: 'integer', minimum: 1, example: 1)
    )]
    #[OA\RequestBody(
        description: 'User modification data',
        required: true,
        content: new OA\JsonContent(
            required: ['username', 'role_id', 'public', 'status'],
            properties: [
                new OA\Property(
                    property: 'username',
                    type: 'string',
                    description: 'Username (5-20 chars, alphanumeric lowercase only)',
                    pattern: '^[a-z0-9]{5,20}$',
                    example: 'newusername'
                ),
                new OA\Property(
                    property: 'password',
                    type: 'string',
                    description: 'New password (optional, min 5 chars, must contain: uppercase, lowercase, number, special character)',
                    example: 'NewPassword123!',
                    nullable: true
                ),
                new OA\Property(
                    property: 'role_id',
                    type: 'integer',
                    description: 'Role ID (only admins/root can modify roles)',
                    example: 2
                ),
                new OA\Property(
                    property: 'public',
                    type: 'boolean',
                    description: 'Whether user profile is public',
                    example: true
                ),
                new OA\Property(
                    property: 'status',
                    type: 'string',
                    description: 'User status',
                    enum: ['active', 'deleted'],
                    example: 'active'
                ),
                new OA\Property(
                    property: 'description',
                    type: 'string',
                    description: 'User description (optional, 5-500 chars, alphanumeric and spaces)',
                    pattern: '^[a-zA-Z0-9\\s]{5,500}$',
                    example: 'This is my user description',
                    nullable: true
                )
            ]
        )
    )]
    #[OA\Response(
        response: 201,
        description: 'User successfully updated',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'success'),
                new OA\Property(property: 'message', type: 'string', example: 'User successfully updated')
            ]
        )
    )]
    #[OA\Response(
        response: 400,
        description: 'Bad Request - Invalid data, validation errors, or permission denied',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', enum: ['error']),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'Invalid data',
                        'Invalid username format',
                        'User already exists',
                        'Invalid password format',
                        'Invalid description format',
                        'Only root users can modify administrators',
                        'Only administrators users can modify coachs',
                        'Invalid role',
                        'Only root users can modify the role of administrators.',
                        'Invalid status',
                        'You cannot modify root users',
                        'The user does not exist',
                        'The user does not match'
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
                new OA\Property(property: 'type', type: 'string', enum: ['error']),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'You are not logged in',
                        'You are not active',
                        'The user does not exist'
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
                new OA\Property(property: 'message', type: 'string', example: 'An error occurred while modifying the user')
            ]
        )
    )]
    #[Route('/modifyUser/{id<\d+>}', name: 'api_modifyUser', methods: ['PUT', 'GET'])]
    public function modifyUser(EntityManagerInterface $entityManager, Request $request, int $id,): JsonResponse
    {
        /** @var \App\Entity\Users $thisuser */
        $thisuser = $this->getUser();

        if (!$thisuser) {
            return $this->json(['type' => 'error', 'message' => 'You are not logged in'], Response::HTTP_UNAUTHORIZED);
        }

        $thisuserId = $thisuser->getUserId();
        $thisuserRoleId = $thisuser->getRole()->getRoleId();
        $thisuserRole = $thisuser->getRole()->getName();
        $thisuserStatus = $thisuser->getStatus();

        if ($thisuserStatus !== 'active') {
            $this->globalService->forceSignOut($entityManager, $thisuserId);
            return $this->json(['type' => 'error', 'message' => 'You are not active'], Response::HTTP_UNAUTHORIZED);
        }

        $user = $entityManager->find(Users::class, $id);

        if (!$user) {
            return $this->json(['type' => 'error', 'message' => 'The user does not exist'], Response::HTTP_UNAUTHORIZED);
        }

        $roleModifyUser = $user->getRole()->getName();

        if ($roleModifyUser === "ROLE_ROOT") {
            return $this->json(['type' => 'error', 'message' => 'You cannot modify root users'], Response::HTTP_BAD_REQUEST);
        }

        if ($thisuserRole !== "ROLE_ROOT" && $roleModifyUser === "ROLE_ADMIN" && $thisuserId !== $id) {
            return $this->json(['type' => 'error', 'message' => 'Only root users can modify administrators'], Response::HTTP_BAD_REQUEST);
        }

        if ($thisuserRole !== "ROLE_ADMIN" && $roleModifyUser === "ROLE_COACH" && $thisuserId !== $id) {
            return $this->json(['type' => 'error', 'message' => 'Only administrators users can modify coachs'], Response::HTTP_BAD_REQUEST);
        }

        if (!$user) {
            return $this->json(['type' => 'error', 'message' => 'The user does not exist'], Response::HTTP_BAD_REQUEST);
        }

        if ($thisuserRole === "ROLE_USER" && $thisuserId  !== $id) {
            return $this->json(['type' => 'error', 'message' => 'The user does not match'], Response::HTTP_BAD_REQUEST);
        }

        $roles = $this->roleService->seeAllRoles($entityManager);

        if (!$roles) {
            return $this->json(['type' => 'warning', 'message' => 'No roles found'], Response::HTTP_OK);
        }

        $rolesData = [];

        foreach ($roles as $data) {
            $rolesData[] = [
                'id' => $data->getRoleId(),
                'name' => $data->getName(),
            ];
        }

        $status = ['active', 'deleted'];

        if ($request->isMethod('GET')) {
            $data = [
                'id_usr' => $user->getUserId(),
                'username' => $user->getDisplayUsername(),
                'description' => $user->getDescription(),
                'public' => $user->getPublic(),
                'status' => $user->getStatus(),
                'role_id' => $user->getRole()->getRoleId(),
                'role_name' => $user->getRole()->getName(),
                'roles' => $rolesData,
                'types_status' => $status
            ];

            return $this->json($data, Response::HTTP_OK);
        }

        if ($request->isMethod('PUT')) {
            try {
                $data = json_decode($request->getContent(), true);

                $username = $this->globalService->validate(strtolower($data['username'] ?? ""));
                $password = $this->globalService->validate($data['password']);
                $roleId = (int)$this->globalService->validate($data['role_id']) ?? "";
                $public = array_key_exists('public', $data)
                    ? filter_var($data['public'], FILTER_VALIDATE_BOOLEAN, FILTER_NULL_ON_FAILURE)
                    : null;
                $status = $this->globalService->validate($data['status'] ?? null);
                $description = $this->globalService->validate($data['description']) ?? "";

                $password_regex = "/^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[\W_])[A-Za-z\d\W_]{5,}$/";
                $username_regex = "/^[a-z0-9]{5,20}$/";
                $description_regex = "/^[a-zA-Z0-9\s]{5,500}$/";

                if ($username === "" || !isset($password) || $roleId === "" || $public === null || $status === null) {
                    return $this->json(['type' => 'error', 'message' => 'Invalid data'], Response::HTTP_BAD_REQUEST);
                }

                if (!preg_match($username_regex, $username)) {
                    return $this->json(['type' => 'error', 'message' => 'Invalid username format'], Response::HTTP_BAD_REQUEST);
                }

                if ($this->userService->userExisting2($id, $username, $entityManager)) {
                    return $this->json(['type' => 'error', 'message' => 'User already exists'], Response::HTTP_BAD_REQUEST);
                }

                $user->setUsername($username);

                if (!empty($password)) {
                    if (!preg_match($password_regex, $password)) {
                        return $this->json(['type' => 'error', 'message' => 'Invalid password format'], Response::HTTP_BAD_REQUEST);
                    }

                    $hashedPassword = $this->userService->hashPassword($password);
                    $user->setPassword($hashedPassword);
                }

                if (!empty($description)) {
                    if (!preg_match($description_regex, $description)) {
                        return $this->json(['type' => 'error', 'message' => 'Invalid description format'], Response::HTTP_BAD_REQUEST);
                    }
                    $user->setDescription($description);
                } else {
                    $user->setDescription(null);
                }

                if ($public !== null) {
                    $user->setPublic($public);
                }

                if ($thisuserRole !== "ROLE_ROOT" && $roleModifyUser === "ROLE_ADMIN" && $thisuserId !== $id) {
                    return $this->json(['type' => 'error', 'message' => 'Only root users can modify administrators'], Response::HTTP_BAD_REQUEST);
                }

                if ($thisuserRole !== "ROLE_ADMIN" && $roleModifyUser === "ROLE_COACH" && $thisuserId !== $id) {
                    return $this->json(['type' => 'error', 'message' => 'Only administrators users can modify coachs'], Response::HTTP_BAD_REQUEST);
                }

                if ($thisuserRole === "ROLE_ADMIN" || $thisuserRole === "ROLE_ROOT") {
                    if (!empty($roleId)) {
                        $role = $this->roleService->roleExisting($roleId, $entityManager);

                        if (!$role) {
                            return $this->json(['type' => 'error', 'message' => 'Invalid role'], Response::HTTP_BAD_REQUEST);
                        }

                        if ($thisuserRole !== "ROLE_ROOT" && $roleModifyUser === "ROLE_ADMIN" && $thisuserRoleId !== $roleId) {
                            return $this->json(['type' => 'error', 'message' => 'Only root users can modify the role of administrators.'], Response::HTTP_BAD_REQUEST);
                        }

                        $user->setRole($role);
                    }
                }

                if (in_array($status, ['active', 'deleted'])) {
                    $user->setStatus($status);
                } else {
                    return $this->json(['type' => 'error', 'message' => 'Invalid status'], Response::HTTP_BAD_REQUEST);
                }

                $entityManager->flush();

                return $this->json(['type' => 'success', 'message' => 'User successfully updated'], Response::HTTP_CREATED);
            } catch (\Exception $e) {
                return $this->json(['type' => 'error', 'message' => 'An error occurred while modifying the user'], Response::HTTP_INTERNAL_SERVER_ERROR);
            }
        }

        return $this->json(['type' => 'error', 'message' => 'Method not allowed'], Response::HTTP_METHOD_NOT_ALLOWED);
    }

    #[OA\Get(
        path: '/api/users/whoami',
        summary: 'Get Current User Information',
        description: 'Retrieve basic information about the currently authenticated user including ID, username, and role',
        tags: ['Users', 'Authentication']
    )]
    #[OA\Response(
        response: 200,
        description: 'Current user information retrieved successfully',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(
                    property: 'ID',
                    type: 'integer',
                    description: 'User unique identifier',
                    example: 1
                ),
                new OA\Property(
                    property: 'USERNAME',
                    type: 'string',
                    description: 'User display username',
                    example: 'username123'
                ),
                new OA\Property(
                    property: 'ROLE',
                    type: 'string',
                    description: 'User role in the system',
                    enum: ['ROLE_ROOT', 'ROLE_ADMIN', 'ROLE_COACH', 'ROLE_USER'],
                    example: 'ROLE_USER'
                )
            ]
        )
    )]
    #[OA\Response(
        response: 401,
        description: 'Unauthorized - User not logged in or not active',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', enum: ['error']),
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
    #[Route('/whoami', name: 'app_whoami', methods: ['GET'])]
    public function whoami(EntityManagerInterface $entityManager): JsonResponse
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

        return $this->json([
            'ID' => $thisuser->getUserId(),
            'USERNAME' => $thisuser->getDisplayUsername(),
            'ROLE' => $thisuser->getRole()->getName(),
        ]);
    }

    #[OA\Post(
        path: '/api/users/sendEmail',
        summary: 'Send Activation Email',
        description: 'Send verification email to user with activation code for pending accounts',
        tags: ['Users', 'Authentication', 'Email']
    )]
    #[OA\RequestBody(
        description: 'User email for activation',
        required: true,
        content: new OA\JsonContent(
            required: ['email'],
            properties: [
                new OA\Property(
                    property: 'email',
                    type: 'string',
                    format: 'email',
                    description: 'User email address (must be valid email format, max 255 chars)',
                    example: 'user@example.com'
                )
            ]
        )
    )]
    #[OA\Response(
        response: 200,
        description: 'Email sent successfully',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'success'),
                new OA\Property(property: 'message', type: 'string', example: 'Email sent successfully')
            ]
        )
    )]
    #[OA\Response(
        response: 400,
        description: 'Bad Request - Invalid data, format, user not found, or user already active',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'Invalid data',
                        'Invalid email format',
                        'The user does not exist',
                        'The user is already active'
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
                new OA\Property(property: 'message', type: 'string', example: 'Error message details...')
            ]
        )
    )]
    #[Route('/sendEmail', name: 'app_activeUser', methods: ['POST'])]
    public function sendEmail(EntityManagerInterface $entityManager, MailerInterface $mailer, Request $request): JsonResponse
    {
        try {
            $data = json_decode($request->getContent(), true);

            $email = $this->globalService->validate(strtolower($data['email'] ?? ""));

            if ($email === "") {
                return $this->json(['type' => 'error', 'message' => 'Invalid data'], Response::HTTP_BAD_REQUEST);
            }

            if (!filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 255) {
                return $this->json(['type' => 'error', 'message' => 'Invalid email format'], Response::HTTP_BAD_REQUEST);
            }

            $user = $entityManager->getRepository(Users::class)->findOneBy(['email' => $email]);

            if (!$user) {
                return $this->json(['type' => 'error', 'message' => 'The user does not exist'], Response::HTTP_BAD_REQUEST);
            }

            if ($user->getStatus() !== "pending") {
                return $this->json(['type' => 'error', 'message' => 'The user is already active'], Response::HTTP_BAD_REQUEST);
            }

            $verificationCode = random_int(100000, 999999);

            $user->setVerificationCode($verificationCode);

            $entityManager->flush();

            $sendEmail = (new Email())
                ->from('fittracktfg@gmail.com')
                ->to($email)
                ->subject('Welcome to FitTrack')
                ->html(
                '<html>
                    <body style="font-family: Arial, sans-serif; background-color: #f0fff0; margin: 0; padding: 0;">
                        <table width="100%" cellpadding="0" cellspacing="0" style="max-width: 600px; margin: auto; background-color: #ffffff; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px rgba(0,0,0,0.05);">
                            <tr>
                                <td align="center">
                                    <img src="cid:fittrack_logo" alt="FitTrack logo" style="width: 200px; height: auto; margin-bottom: 20px;" />
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <h1 style="color: #2e7d32; text-align: center;">Welcome to FitTrack!</h1>
                                    <p style="color: #333333; font-size: 16px; text-align: center;">
                                        Thank you for registering with <strong>FitTrack</strong>.<br />
                                        We are delighted to have you join our community.
                                    </p>
                                    <p style="color: #333333; font-size: 16px; text-align: center;">
                                        Here is your verification code:
                                    </p>
                                    <h2 style="color: #4caf50; text-align: center;">' . $verificationCode . '</h2>
                                    <p style="color: #333333; font-size: 16px; text-align: center;">
                                        Enjoy the app and reach your goals in a smarter way!
                                    </p>
                                    <div style="text-align: center; margin-top: 30px;">
                                        <a href="https://fittrackapp.vercel.app/EmailCheck" style="background-color: #4caf50; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; font-weight: bold;">
                                            Go to FitTrack
                                        </a>
                                    </div>
                                    <p style="text-align: center; color: #999999; font-size: 12px; margin-top: 30px;">
                                        &copy; ' . date("Y") . ' FitTrack. All rights reserved.
                                    </p>
                                </td>
                            </tr>
                        </table>
                    </body>
                </html>'
                )
                ->embedFromPath('assets/img/FTLogo.png', 'fittrack_logo');

            $mailer->send($sendEmail);

            return $this->json(['type' => 'success', 'message' => 'Email sent successfully'], Response::HTTP_OK);
        } catch (\Exception $e) {
            return $this->json(['type' => 'error', 'message' => $e->getMessage()], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    #[OA\Post(
        path: '/api/users/checkCode',
        summary: 'Verify Activation Code',
        description: 'Verify user activation code and activate pending user account',
        tags: ['Users', 'Authentication', 'Verification']
    )]
    #[OA\RequestBody(
        description: 'Verification code for account activation',
        required: true,
        content: new OA\JsonContent(
            required: ['verificationCode'],
            properties: [
                new OA\Property(
                    property: 'verificationCode',
                    type: 'integer',
                    description: 'User verification code (6-digit number between 100000-999999)',
                    example: 123456,
                    minimum: 100000,
                    maximum: 999999
                )
            ]
        )
    )]
    #[OA\Response(
        response: 201,
        description: 'User successfully activated',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'success'),
                new OA\Property(property: 'message', type: 'string', example: 'User successfully activated')
            ]
        )
    )]
    #[OA\Response(
        response: 400,
        description: 'Bad Request - Invalid data, format, or verification code',
        content: new OA\JsonContent(
            properties: [
                new OA\Property(property: 'type', type: 'string', example: 'error'),
                new OA\Property(
                    property: 'message',
                    type: 'string',
                    enum: [
                        'Invalid data',
                        'Invalid verification code format',
                        'Invalid verification code'
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
                new OA\Property(property: 'message', type: 'string', example: 'An error has occurred with the verification code')
            ]
        )
    )]
    #[Route('/checkCode', name: 'api_checkCode', methods: ['POST'])]
    public function checkCode(EntityManagerInterface $entityManager, Request $request): JsonResponse
    {
        try {
            $data = json_decode($request->getContent(), true);

            $verificationCode = (int)$this->globalService->validate($data['verificationCode']) ?? "";

            if ($verificationCode === "") {
                return $this->json(['type' => 'error', 'message' => 'Invalid data'], Response::HTTP_BAD_REQUEST);
            }

            if ($verificationCode > 999999 || $verificationCode < 100000) {
                return $this->json(['type' => 'error', 'message' => 'Invalid verification code format'], Response::HTTP_BAD_REQUEST);
            }

            $code = $entityManager->getRepository(Users::class)->findOneBy(['verification_code' => $verificationCode]);

            if (!$code) {
                return $this->json(['type' => 'error', 'message' => 'Invalid verification code'], Response::HTTP_BAD_REQUEST);
            }

            $code->setVerificationCode(null);
            $code->setStatus('active');

            $entityManager->persist($code);
            $entityManager->flush();

            return $this->json(['type' => 'success', 'message' => 'User successfully activated'], Response::HTTP_CREATED);
        } catch (\Exception $e) {
            return $this->json(['type' => 'error', 'message' => 'An error has occurred with the verification code'], Response::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}
