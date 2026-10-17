import { describe, expect, it, beforeEach } from 'vitest';
import { HttpException, HttpStatus } from '@nestjs/common';

import { AuthController, _resetAuthStateForTests } from '../controllers/auth.controller.js';
import { identityStore } from '../repositories/identity.repository.js';
import { sessionStore } from '../repositories/session.repository.js';
import type { AuthIdentity } from '../types/index.js';

function seedIdentity(overrides: Partial<AuthIdentity> = {}): AuthIdentity {
  const identity = {
    userId: 'user-1303',
    clinicId: 'clinic-1303',
    email: 'owner@clinic.test',
    passwordHash: 'unused-in-these-tests',
    role: 'owner',
    status: 'active',
    createdAt: new Date().toISOString(),
    ...overrides,
  } as AuthIdentity;
  identityStore.save(identity);
  return identity;
}

/** The controller only writes through res.json(). */
function fakeRes() {
  const state: { body?: unknown } = {};
  return {
    res: {
      json: (body: unknown) => {
        state.body = body;
        return body;
      },
    } as never,
    state,
  };
}

function seedSession(refreshToken: string): void {
  sessionStore.save({
    sessionId: `access-${refreshToken}`,
    userId: 'user-1303',
    clinicId: 'clinic-1303',
    accessToken: `access-${refreshToken}`,
    refreshToken,
  });
}

async function refreshAndCatch(controller: AuthController, refreshToken: string) {
  try {
    await controller.refresh({ refreshToken }, 'req', '127.0.0.1', fakeRes().res);
    return null;
  } catch (error) {
    return error as HttpException;
  }
}

describe('refresh must not outlive the identity (#1303)', () => {
  beforeEach(() => {
    identityStore._reset();
    _resetAuthStateForTests();
  });

  it('issues no token and revokes the session when the identity is gone', async () => {
    seedIdentity();
    const controller = new AuthController();
    seedSession('refresh-gone');

    identityStore._reset(); // identity deleted while the refresh token is still valid

    const error = await refreshAndCatch(controller, 'refresh-gone');
    expect(error).toBeInstanceOf(HttpException);
    expect(error?.getStatus()).toBe(HttpStatus.UNAUTHORIZED);
    expect(error?.getResponse()).toMatchObject({ error: 'AUTH_TOKEN_INVALID' });

    // The session was revoked: restoring the identity does not resurrect it.
    seedIdentity();
    const retry = await refreshAndCatch(controller, 'refresh-gone');
    expect(retry).toBeInstanceOf(HttpException);
  });

  it.each(['suspended', 'locked', 'pending'] as const)(
    'refuses to refresh a %s account and revokes the session',
    async (status) => {
      seedIdentity({ status });
      const controller = new AuthController();
      const token = `refresh-${status}`;
      seedSession(token);

      const error = await refreshAndCatch(controller, token);
      expect(error).toBeInstanceOf(HttpException);
      expect(error?.getStatus()).toBeGreaterThanOrEqual(400);

      const again = await refreshAndCatch(controller, token);
      expect(again).toBeInstanceOf(HttpException);
    },
  );

  it('issues a token for a healthy identity', async () => {
    seedIdentity();
    const controller = new AuthController();
    seedSession('refresh-ok');

    const { res, state } = fakeRes();
    await controller.refresh({ refreshToken: 'refresh-ok' }, 'req', '127.0.0.1', res);

    const body = state.body as { accessToken?: string; refreshToken?: string };
    expect(body.accessToken).toBeTruthy();
    expect(body.refreshToken).toBeTruthy();
    expect(body.refreshToken).not.toBe('refresh-ok');
  });
});

describe('login refusal for unknown identities (#1303 contrast)', () => {
  beforeEach(() => {
    identityStore._reset();
    _resetAuthStateForTests();
  });

  it('does not mint a token for an email that is not stored', async () => {
    const controller = new AuthController();
    const { res, state } = fakeRes();
    await expect(
      controller.login({ email: 'ghost@clinic.test', password: 'whatever' }, 'req', '127.0.0.1', res),
    ).rejects.toBeInstanceOf(HttpException);
    expect(state.body).toBeUndefined();
  });
});
