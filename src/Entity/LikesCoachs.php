<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Doctrine\DBAL\Types\Types;
use Symfony\Component\Validator\Constraints as Assert;

#[ORM\Entity]
#[ORM\Table(name: 'likes_coachs')]
class LikesCoachs
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(name: 'coachLike_id', type: Types::INTEGER)]
    private ?int $coachLike_id = null;

    #[ORM\Column(type: Types::INTEGER)]
    #[Assert\NotNull]
    private ?int $likes = null;

    #[ORM\OneToOne(inversedBy: 'likesCoachs', targetEntity: Users::class)]
    #[ORM\JoinColumn(name: 'coach_id', referencedColumnName: 'user_id', nullable: false)]
    private ?Users $coach = null;

    public function getChlikeId(): ?int
    {
        return $this->coachLike_id;
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

    public function getCoach(): ?Users
    {
        return $this->coach;
    }

    public function setCoach(?Users $coach): self
    {
        $this->coach = $coach;
        return $this;
    }
}
