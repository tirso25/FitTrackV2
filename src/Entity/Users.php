<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Doctrine\DBAL\Types\Types;
use Doctrine\Common\Collections\Collection;
use Doctrine\Common\Collections\ArrayCollection;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;
use Symfony\Component\Security\Core\User\PasswordAuthenticatedUserInterface;
use Symfony\Component\Security\Core\User\UserInterface;
use Symfony\Component\Validator\Constraints as Assert;

#[ORM\Entity]
#[ORM\Table(name: 'users')]
#[UniqueEntity(fields: ['email'], message: 'There is already an account with this email')]
#[UniqueEntity(fields: ['username'], message: 'This username is already taken')]
class Users implements UserInterface, PasswordAuthenticatedUserInterface
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: Types::INTEGER)]
    private ?int $user_id = null;

    #[ORM\Column(length: 255, type: Types::STRING, unique: true)]
    #[Assert\NotBlank(message: "The email cannot be empty")]
    #[Assert\Email]
    private ?string $email = null;

    #[ORM\Column(length: 20, type: Types::STRING, unique: true)]
    #[Assert\NotBlank(message: "The username cannot be empty")]
    private ?string $username = null;

    #[ORM\Column(length: 255, type: Types::TEXT)]
    #[Assert\NotNull]
    private ?string $password = null;

    #[ORM\ManyToOne(targetEntity: Roles::class, inversedBy: 'users')]
    #[ORM\JoinColumn(name: 'role', referencedColumnName: 'role_id', nullable: false)]
    #[Assert\NotNull]
    private ?Roles $role = null;

    #[Assert\Choice(choices: ['pending', 'active', 'deleted'], message: 'Choose a valid status.')]
    #[ORM\Column(type: Types::STRING, length: 20, options: ['default' => 'pending'])]
    private ?string $status = 'pending';

    #[ORM\Column(length: 255, type: Types::STRING, nullable: true)]
    private ?string $token = null;

    #[ORM\Column(type: Types::DATETIME_MUTABLE, options: ['default' => 'CURRENT_TIMESTAMP'])]
    private ?\DateTime $date_union = null;

    #[ORM\Column(type: Types::BOOLEAN, options: ['default' => true])]
    private ?bool $public = null;

    #[ORM\Column(type: Types::INTEGER, nullable: true)]
    private ?int $verification_code = null;

    #[ORM\Column(length: 500, type: Types::STRING, nullable: true)]
    private ?string $description = null;

    #[ORM\OneToMany(mappedBy: 'user', targetEntity: FavoritesExercises::class, orphanRemoval: true)]
    private Collection $favoriteExercises;

    #[ORM\OneToMany(mappedBy: 'user', targetEntity: Exercises::class, orphanRemoval: true)]
    private Collection $exercises;

    #[ORM\OneToMany(mappedBy: 'user', targetEntity: FavoritesCoachs::class, orphanRemoval: true)]
    private Collection $favoriteCoachs;

    #[ORM\OneToMany(mappedBy: 'coach', targetEntity: FavoritesCoachs::class, orphanRemoval: true)]
    private Collection $fans;

    #[ORM\OneToOne(mappedBy: 'coach', targetEntity: LikesCoachs::class, cascade: ['persist', 'remove'])]
    private ?LikesCoachs $likesCoachs = null;

    public function __construct()
    {
        $this->favoriteExercises = new ArrayCollection();
        $this->exercises = new ArrayCollection();
        $this->favoriteCoachs = new ArrayCollection();
        $this->fans = new ArrayCollection();
    }

    public function getUserId(): ?int
    {
        return $this->user_id;
    }

    public function getEmail(): ?string
    {
        return $this->email;
    }

    public function setEmail(string $email): static
    {
        $this->email = $email;

        return $this;
    }

    public function getDisplayUsername(): ?string
    {
        return $this->username;
    }

    public function setUsername(string $username): static
    {
        $this->username = $username;

        return $this;
    }

    public function getPassword(): ?string
    {
        return $this->password;
    }

    public function setPassword(string $password): static
    {
        $this->password = $password;

        return $this;
    }

    public function getRole(): ?Roles
    {
        return $this->role;
    }

    public function setRole(?Roles $role): static
    {
        $this->role = $role;

        return $this;
    }

    public function getStatus()
    {
        return $this->status;
    }

    public function setStatus($status)
    {
        $this->status = $status;

        return $this;
    }

    public function getFavoriteExercises(): Collection
    {
        return $this->favoriteExercises;
    }

    public function setFavoriteExercises(Collection $favoriteExercises): static
    {
        $this->favoriteExercises = $favoriteExercises;

        return $this;
    }

    public function getToken(): ?string
    {
        return $this->token;
    }

    public function setToken(?string $token): static
    {
        $this->token = $token;

        return $this;
    }

    public function getDateUnion(): ?\DateTime
    {
        return $this->date_union;
    }

    public function setDateUnion(?\DateTime $date_union): static
    {
        $this->date_union = $date_union;

        return $this;
    }

    public function getPublic(): ?bool
    {
        return $this->public;
    }

    public function setPublic(bool $public): static
    {
        $this->public = $public;

        return $this;
    }

    public function getVerificationCode(): ?int
    {
        return $this->verification_code;
    }

    public function setVerificationCode($verification_code): static
    {
        $this->verification_code = $verification_code;

        return $this;
    }

    public function getDescription(): ?string
    {
        return $this->description;
    }

    public function setDescription(?string $description): static
    {
        $this->description = $description;
        return $this;
    }

    public function getExercises(): Collection
    {
        return $this->exercises;
    }

    public function getUserIdentifier(): string
    {
        return $this->email ?? '';
    }

    public function getRoles(): array
    {
        return [$this->role?->getName() ?? 'ROLE_USER'];
    }

    public function eraseCredentials(): void {}

    public function getUsername(): string
    {
        return $this->email ?? '';
    }

    public function getFavoriteCoachs(): Collection
    {
        return $this->favoriteCoachs;
    }

    public function getFans(): Collection
    {
        return $this->fans;
    }

    public function getCoachLikes()
    {
        return $this->likesCoachs;
    }

    public function setCoachLikes($likesCoachs)
    {
        $this->likesCoachs = $likesCoachs;

        return $this;
    }
}
