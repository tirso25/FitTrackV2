<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Doctrine\DBAL\Types\Types;

#[ORM\Entity]
#[ORM\Table(name: 'favorites_coachs')]
class FavoritesCoachs
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(name: 'coachesFavorites_id', type: Types::INTEGER)]
    private ?int $coachesFavorites_id = null;

    #[ORM\Column(type: Types::BOOLEAN, options: ['default' => true])]
    private ?bool $active = true;

    #[ORM\ManyToOne(targetEntity: Users::class, inversedBy: 'fans')]
    #[ORM\JoinColumn(name: 'coach_id', referencedColumnName: 'user_id', nullable: false)]
    private ?Users $coach = null;

    #[ORM\ManyToOne(targetEntity: Users::class, inversedBy: 'favoriteCoachs')]
    #[ORM\JoinColumn(name: 'user_id', referencedColumnName: 'user_id', nullable: false)]
    private ?Users $user = null;

    public function getCoachesFavoritesId(): ?int
    {
        return $this->coachesFavorites_id;
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

    public function getCoach(): ?Users
    {
        return $this->coach;
    }

    public function setCoach(?Users $coach): self
    {
        $this->coach = $coach;

        return $this;
    }

    public function getUser(): ?Users
    {
        return $this->user;
    }

    public function setUser(?Users $user): self
    {
        $this->user = $user;

        return $this;
    }
}
