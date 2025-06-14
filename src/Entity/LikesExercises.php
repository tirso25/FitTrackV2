<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Doctrine\DBAL\Types\Types;
use Symfony\Component\Validator\Constraints as Assert;

#[ORM\Entity]
#[ORM\Table(name: 'likes_exercises')]
class LikesExercises
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(name: 'exerciseLike_id', type: Types::INTEGER)]
    private ?int $exerciseLike_id = null;

    #[ORM\Column(type: Types::INTEGER)]
    #[Assert\NotNull]
    private ?int $likes = null;

    #[ORM\OneToOne(inversedBy: 'likesExercises', targetEntity: Exercises::class)]
    #[ORM\JoinColumn(name: 'exercise_id', referencedColumnName: 'exercise_id', nullable: false)]
    private ?Exercises $exercise = null;

    public function getExrlikeId(): ?int
    {
        return $this->exerciseLike_id;
    }

    public function getLikes(): ?int
    {
        return $this->likes;
    }

    public function setLikes(int $likes): static
    {
        $this->likes = $likes;
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
}
