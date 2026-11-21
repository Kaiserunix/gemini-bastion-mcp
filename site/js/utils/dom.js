/**
 * Safe HTML escaping & domain normalization utilities
 */
export function escapeHtml(value) {
  return String(value)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

export function normalizeDomainInput(raw) {
  const trimmed = String(raw || '').trim().replace(/\/+$/, '');
  if (!trimmed) {
    return {
      origin: 'https://mcp.yourdomain.com',
      host: 'mcp.yourdomain.com',
    };
  }
  const candidate = /^https?:\/\//i.test(trimmed) ? trimmed : `https://${trimmed}`;
  try {
    const parsed = new URL(candidate);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      throw new Error('Unsupported protocol');
    }
    return {
      origin: parsed.origin,
      host: parsed.host,
    };
  } catch {
    return {
      origin: 'https://mcp.yourdomain.com',
      host: 'mcp.yourdomain.com',
    };
  }
}
