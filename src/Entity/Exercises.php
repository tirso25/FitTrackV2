<?php

namespace App\Entity;

use Doctrine\DBAL\Types\Types;
use Doctrine\ORM\Mapping as ORM;
use Doctrine\Common\Collections\Collection;
use Doctrine\Common\Collections\ArrayCollection;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;
use Symfony\Component\Validator\Constraints as Assert;

#[ORM\Entity]
#[ORM\Table(name: 'exercises')]
#[UniqueEntity(fields: ['name'], message: 'This exercise name is already taken')]
class Exercises
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: Types::INTEGER)]
    private ?int $exercise_id = null;

    #[ORM\Column(length: 30, type: Types::STRING, unique: true)]
    #[Assert\NotBlank(message: "The name cannot be empty")]
    private ?string $name = null;

    #[ORM\Column(length: 500, type: Types::STRING)]
    #[Assert\NotBlank(message: "The description cannot be empty")]
    private ?string $description = null;

    #[ORM\ManyToOne(targetEntity: Categories::class, inversedBy: 'exercises')]
    #[ORM\JoinColumn(name: 'category', referencedColumnName: 'category_id', nullable: false)]
    #[Assert\NotNull]
    private ?Categories $category = null;

    #[ORM\Column(type: Types::BOOLEAN, options: ['default' => true])]
    private ?bool $active = null;

    #[ORM\Column(type: Types::DATETIME_IMMUTABLE, options: ['default' => 'CURRENT_TIMESTAMP'])]
    private \DateTimeInterface $createdAt;

    #[ORM\OneToMany(targetEntity: FavoritesExercises::class, mappedBy: 'exercise', orphanRemoval: true)]
    private Collection $favoriteExercises;

    #[ORM\OneToOne(mappedBy: 'exercise', targetEntity: LikesExercises::class, cascade: ['persist', 'remove'])]
    private ?LikesExercises $likesExercises = null;

    #[ORM\ManyToOne(targetEntity: Users::class, inversedBy: 'exercises')]
    #[ORM\JoinColumn(name: 'user_id', referencedColumnName: 'user_id', nullable: false)]
    private ?Users $user = null;

    public function __construct()
    {
        $this->favoriteExercises = new ArrayCollection();
    }

    public function getExerciseId(): ?int
    {
        return $this->exercise_id;
    }

    public function getName(): ?string
    {
        return $this->name;
    }

    public function setName(string $name): static
    {
        $this->name = $name;
        return $this;
    }

    public function getDescription(): ?string
    {
        return $this->description;
    }

    public function setDescription(string $description): static
    {
        $this->description = $description;
        return $this;
    }

    public function getCategory(): ?Categories
    {
        return $this->category;
    }

    public function setCategory(Categories $category): static
    {
        $this->category = $category;
        return $this;
    }

    public function getActive(): ?bool
    {
        return $this->active;
    }

    public function setActive(bool $active): static
    {
        $this->active = $active;
        return $this;
    }

    public function getCreatedAt(): \DateTimeInterface
    {
        return $this->createdAt;
    }

    public function setCreatedAt(\DateTimeInterface $createdAt): void
    {
        $this->createdAt = $createdAt;
    }

    public function getFavoriteExercises()
    {
        return $this->favoriteExercises;
    }

    public function setFavoriteExercises($favoriteExercises)
    {
        $this->favoriteExercises = $favoriteExercises;
        return $this;
    }

    public function getExerciseLikes()
    {
        return $this->likesExercises;
    }

    public function setExerciseLikes($likesExercises)
    {
        $this->likesExercises = $likesExercises;

        return $this;
    }

    public function getUser(): ?Users
    {
        return $this->user;
    }

    public function setUser(?Users $user): static
    {
        $this->user = $user;

        return $this;
    }
}
