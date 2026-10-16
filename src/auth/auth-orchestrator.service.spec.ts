import { Test } from '@nestjs/testing';
import { Logger } from '@nestjs/common';

import { AuthOrchestratorService } from './auth-orchestrator.service';

describe('AuthOrchestratorService', () => {
  let service: AuthOrchestratorService;

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      providers: [AuthOrchestratorService],
    }).compile();

    service = moduleRef.get(AuthOrchestratorService);
  });

  describe('validatePayload', () => {
    it('returns true for a valid authProvider', () => {
      const result = service.validatePayload({
        authProvider: 'google',
        authId: 'auth-id-123',
        email: 'user@example.com',
        displayName: 'Test User',
      });

      expect(result).toBe(true);
    });

    it('returns false for an invalid authProvider', () => {
      const result = service.validatePayload({
        authProvider: 'not-a-real-provider',
        authId: 'auth-id-123',
        email: 'user@example.com',
        displayName: 'Test User',
      });

      expect(result).toBe(false);
    });

    it('logs a bounded rejection without leaking authId or email', () => {
      const warnSpy = jest
        .spyOn(Logger.prototype, 'warn')
        .mockImplementation(() => undefined);

      const authId = 'sensitive-auth-id-abc';
      const email = 'sensitive-user@example.com';

      const result = service.validatePayload({
        authProvider: 'not-a-real-provider',
        authId,
        email,
        displayName: 'Sensitive User',
      });

      expect(result).toBe(false);
      expect(warnSpy).toHaveBeenCalled();

      const serializedArgs = JSON.stringify(warnSpy.mock.calls);
      expect(serializedArgs).not.toContain(authId);
      expect(serializedArgs).not.toContain(email);

      const [, context] = warnSpy.mock.calls[0];
      expect(JSON.stringify(context)).toMatch(/error/i);

      warnSpy.mockRestore();
    });
  });
});
