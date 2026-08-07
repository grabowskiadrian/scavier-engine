<?php

namespace Scavier\Tests\Engine;

use PHPUnit\Framework\TestCase;
use Scavier\Engine\Context;

final class ContextTest extends TestCase
{
    public function testSetAndGet(): void
    {
        $context = new Context();
        $object = new \stdClass();
        $object->value = 'test';

        $context->set($object);

        $this->assertSame($object, $context->get(\stdClass::class));
    }

    public function testGetReturnsNullForMissing(): void
    {
        $context = new Context();

        $this->assertNull($context->get(\stdClass::class));
    }

    public function testHas(): void
    {
        $context = new Context();

        $this->assertFalse($context->has(\stdClass::class));

        $context->set(new \stdClass());

        $this->assertTrue($context->has(\stdClass::class));
    }

    public function testAll(): void
    {
        $context = new Context();

        $this->assertSame([], $context->all());

        $obj = new \stdClass();
        $context->set($obj);

        $this->assertSame([\stdClass::class => $obj], $context->all());
    }

    public function testDetectorResults(): void
    {
        $context = new Context();
        $result = ['server' => ['value' => 'nginx']];

        $this->assertFalse($context->hasDetectorResult('SomeDetector'));
        $this->assertNull($context->getDetectorResult('SomeDetector'));

        $context->setDetectorResult('SomeDetector', $result);

        $this->assertTrue($context->hasDetectorResult('SomeDetector'));
        $this->assertSame($result, $context->getDetectorResult('SomeDetector'));
    }
}
