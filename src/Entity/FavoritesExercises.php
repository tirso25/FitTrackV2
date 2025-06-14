<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Doctrine\DBAL\Types\Types;

#[ORM\Entity]
#[ORM\Table(name: 'favorites_exercises')]
class FavoritesExercises
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(name: 'exercisesFavorite_id', type: Types::INTEGER)]
    private ?int $exercisesFavorite_id = null;

    #[ORM\Column(type: Types::BOOLEAN, options: ['default' => true])]
    private ?bool $active = null;

    #[ORM\ManyToOne(targetEntity: Users::class, inversedBy: 'favoriteExercises')]
    #[ORM\JoinColumn(name: 'user_id', referencedColumnName: 'user_id', nullable: false)]
    private ?Users $user = null;

    #[ORM\ManyToOne(targetEntity: Exercises::class, inversedBy: 'favoriteExercises')]
    #[ORM\JoinColumn(name: 'exercise_id', referencedColumnName: 'exercise_id', nullable: false)]
    private ?Exercises $exercise = null;

    public function getUser(): ?Users
    {
        return $this->user;
    }

    public function setUser(?Users $user): self
    {
        $this->user = $user;
        return $this;
    }

    public function getExercise(): ?Exercises
    {
        return $this->exercise;
    }

    public function setExercise(?Exercises $exercise): self
    {
        $this->exercise = $exercise;
        return $this;
    }

    public function getExercisesFavoriteId(): ?int
    {
        return $this->exercisesFavorite_id;
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
}
