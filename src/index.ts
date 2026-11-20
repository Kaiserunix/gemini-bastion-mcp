import { serve } from '@hono/node-server';
import { createGatewayApp } from './app.js';

function main(): void {
  const gateway = createGatewayApp();
  const server = serve(
    {
      fetch: gateway.app.fetch,
      port: gateway.config.port,
    },
    (info) => {
      console.log(
        `[omni-mcp-gateway] Listening on http://0.0.0.0:${info.port} (publicDomain=${gateway.config.publicDomain})`,
      );
    },
  );

  let shuttingDown = false;
  const handleSignal = (signal: string) => {
    if (shuttingDown) return;
    shuttingDown = true;
    console.log(`[omni-mcp-gateway] Received ${signal}, shutting down gracefully...`);

    const forceTimer = setTimeout(() => {
      console.error('[omni-mcp-gateway] Forced exit after shutdown timeout.');
      process.exit(1);
    }, 10_000);
    forceTimer.unref?.();

    server.close(async () => {
      await gateway.shutdown();
      clearTimeout(forceTimer);
      process.exit(0);
    });
  };

  process.on('SIGINT', () => handleSignal('SIGINT'));
  process.on('SIGTERM', () => handleSignal('SIGTERM'));
}

main();
