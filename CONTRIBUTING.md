# Contributing to Scavier

Thanks for your interest in contributing! Here's how to get started.

## Development Setup

```bash
git clone https://github.com/grabowskiadrian/scavier.git
cd scavier
composer install
php -S localhost:8000 -t public
```

Requires PHP 8.3+ with curl and dom extensions.

## Running Tests

```bash
composer test
```

All tests must pass before submitting a PR.

## Adding a Detector

1. Create a class in `src/Detector/` that extends `Scavier\Engine\Contract\Detector`
2. Declare dependencies via `dependencies()` (e.g. which collectors it needs)
3. Implement `detect(Context $context): ?array` — return structured data or `null`
4. Add tests in `tests/Detector/`

The detector is auto-discovered — no registration needed.

## Adding a Collector

1. Create a class in `src/Collector/` that extends `Scavier\Engine\Contract\Collector`
2. Create a data object in `src/Collector/Data/` with `readonly` properties
3. Implement `execute(Target $target, Context $context): void` — fetch data and store via `$context->set()`
4. Add tests in `tests/Collector/`

## Pull Request Process

1. Fork the repo and create a feature branch (`git checkout -b feature/my-change`)
2. Write tests for your changes
3. Make sure `composer test` passes
4. Keep commits focused — one logical change per commit
5. Submit a PR with a clear description of what and why

## Code Style

- Follow existing patterns in the codebase
- Use `readonly` properties for data objects
- Use typed properties and return types
- Keep classes focused and small

## Reporting Issues

Use [GitHub Issues](https://github.com/grabowskiadrian/scavier/issues). Include:
- What you expected to happen
- What actually happened
- Steps to reproduce
- PHP version and environment details
