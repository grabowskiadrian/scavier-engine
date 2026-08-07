<?php

namespace Scavier\Engine;

use RuntimeException;

/**
 * Resolves dependency order using topological sort (DFS).
 * Detects circular dependencies and throws RuntimeException.
 */
final class DependencyResolver
{
    /**
     * @template T
     *
     * @param array<class-string<T>,T> $available
     * @param array<class-string<T>> $roots
     *
     * @return array<T>
     */
    public function resolve(array $available, array $roots): array
    {
        $resolved = [];
        $visiting = [];

        foreach ($roots as $root) {
            $this->visit(
                $root,
                $available,
                $resolved,
                $visiting
            );
        }

        return array_values($resolved);
    }

    /**
     * @template T
     *
     * @param class-string<T> $class
     * @param array<class-string<T>,T> $available
     * @param array<class-string<T>,T> $resolved
     * @param array<class-string,bool> $visiting
     */
    private function visit(
        string $class,
        array $available,
        array &$resolved,
        array &$visiting
    ): void {

        if (isset($resolved[$class])) {
            return;
        }

        if (isset($visiting[$class])) {
            throw new RuntimeException(
                "Circular dependency detected: {$class}"
            );
        }

        if (!isset($available[$class])) {
            return;
        }

        $visiting[$class] = true;

        foreach ($class::dependencies() as $dependency) {
            if (isset($available[$dependency])) {
                $this->visit(
                    $dependency,
                    $available,
                    $resolved,
                    $visiting
                );
            }
        }

        unset($visiting[$class]);

        $resolved[$class] = $available[$class];
    }
}