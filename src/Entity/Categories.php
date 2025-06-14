<?php

namespace App\Entity;

use Doctrine\ORM\Mapping as ORM;
use Doctrine\Common\Collections\Collection;
use Doctrine\Common\Collections\ArrayCollection;
use Symfony\Bridge\Doctrine\Validator\Constraints\UniqueEntity;
use Symfony\Component\Validator\Constraints as Assert;
use Doctrine\DBAL\Types\Types;

#[ORM\Entity]
#[ORM\Table(name: 'categories')]
#[UniqueEntity(fields: ['name'], message: 'This name is already taken')]
class Categories
{
    #[ORM\Id]
    #[ORM\GeneratedValue]
    #[ORM\Column(type: 'integer')]
    private ?int $category_id = null;

    #[ORM\Column(length: 50, type: Types::STRING, unique: true)]
    #[Assert\NotBlank(message: "The name cannot be empty")]
    private ?string $name = null;

    #[ORM\Column(type: Types::BOOLEAN, options: ['default' => true])]
    private ?bool $active = null;

    #[ORM\OneToMany(targetEntity: Exercises::class, mappedBy: 'category', orphanRemoval: true)]
    private Collection $exercises;

    public function __construct()
    {
        $this->exercises = new ArrayCollection();
    }

    public function getCategoryId(): ?int
    {
        return $this->category_id;
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

    public function getExercises()
    {
        return $this->exercises;
    }

    public function setExercises($exercises)
    {
        $this->exercises = $exercises;

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
}
