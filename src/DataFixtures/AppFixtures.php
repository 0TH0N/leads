<?php

namespace App\DataFixtures;

use App\Entity\Lead;
use App\Entity\User;
use Doctrine\Bundle\FixturesBundle\Fixture;
use Doctrine\Common\Persistence\ObjectManager;
use Symfony\Component\Security\Core\Encoder\UserPasswordEncoderInterface;

class AppFixtures extends Fixture
{
    /**
     * @var UserPasswordEncoderInterface
     */
    private $passwordEncoder;

    /**
     * AppFixtures constructor.
     *
     * @param UserPasswordEncoderInterface $passwordEncoder
     */
    public function __construct(UserPasswordEncoderInterface $passwordEncoder)
    {
        $this->passwordEncoder = $passwordEncoder;
    }

    public function load(ObjectManager $manager)
    {
        $names = ['question', 'order', 'complaint', 'other'];
        $sources = ['google', 'yandex', '2gis', 'other'];
        $statuses = ['new', 'active', 'deffered', 'finished'];

        $user = new User();
        $user->setUsername("User_admin");
        $user->setPassword($this->passwordEncoder->encodePassword($user, '123456'));
        $user->setRoles(['ROLE_SUPER_ADMIN']);
        $manager->persist($user);

        for ($i = 1; $i <= 5; $i++) {
            $user = new User();
            $user->setUsername("User_{$i}");
            $user->setPassword($this->passwordEncoder->encodePassword($user, '123456'));
            $manager->persist($user);

            for ($j = 1; $j <= 50; $j++) {
                $name = $names[array_rand($names)];
                $source = $sources[array_rand($sources)];
                $status = $statuses[array_rand($statuses)];
                $lead = new Lead($user, $name, $source, $status);
                $manager->persist($lead);
            }
        }

        $manager->flush();
    }
}
