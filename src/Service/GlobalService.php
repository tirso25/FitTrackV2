<?php

namespace App\Service;

class GlobalService
{
    public function __construct(
        private UserService $userService,
    ) {}

    public function validate($data)
    {
        $data = (string)($data ?? '');
        return htmlspecialchars(stripslashes(trim($data)), ENT_QUOTES, 'UTF-8');
    }

    //!!ELIMINAR EL JWT CON JS DESDE EL FRONT
    public function forceSignOut($entityManager, int $id_user)
    {
        if ($id_user) {
            $this->userService->removeToken($entityManager, $id_user);
            if (isset($_COOKIE['rememberToken'])) {
                setcookie("rememberToken", "", [
                    'expires' => time() - 3600,
                    'path' => '/',
                    'secure' => true,
                    'httponly' => true,
                    'samesite' => 'None'
                ]);

                unset($_COOKIE['rememberToken']);
            }
        }
    }
}
