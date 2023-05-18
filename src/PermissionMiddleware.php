<?php

namespace Prezto;

use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Server\RequestHandlerInterface;

class PermissionMiddleware implements MiddlewareInterface
{
    /**
     * @var array
     */
    protected array $patterns;

    /**
     * @var int|null
     */
    protected ?int $mode = null;

    /**
     * @param array $patterns
     * @param int $mode
     */
    public function __construct(array $patterns = [], int $mode = Mode::ALLOW)
    {
        $this->patterns = $patterns;
        $this->mode = $mode;
    }
  
    /**
     * {@inheritdoc}
     */
    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $isAllowed = null;

        if ($this->mode === Mode::ALLOW) {
            $isAllowed = $this->allow($request);
        } elseif ($this->mode === Mode::DENY) {
            $isAllowed = $this->deny($request);
        }

        if (!$isAllowed) {
            $request =  $request->withStatus(401);
        }

       return $handler->handle($request);
    }

    /**
     * The default allow rule set allows all connections through unless otherwise stated
     * @param ServerRequestInterface $request
     * @return bool
     */
    public function allow(ServerRequestInterface $request): bool
    {
        foreach ($this->patterns as $regex)
            if (preg_match(sprintf("#^%s$#i", $regex), $request->getUri()->getPath()))
                return false;

        return true;
    }

    /**
     * A default deny rule set will deny all connections through  unless a url matches a specific rule.
     * @param ServerRequestInterface $request
     * @return bool
     */
    public function deny(ServerRequestInterface $request): bool
    {
        foreach ($this->patterns as $regex)
            if (preg_match(sprintf("#^%s$#i", $regex), $request->getUri()->getPath()))
                return true;

        return false;
    }
}
