import { Injectable, Logger, BadRequestException } from '@nestjs/common';
import {
  AuthProvider,
  isValidAuthProvider,
  getValidProviderNames,
} from './auth-provider.enum';

/**
 * Validates authentication payloads from identity providers.
 *
 * Fail-closed: invalid or missing claims are rejected.
 */
@Injectable()
export class AuthPayloadValidator {
  authId!: string;
  email?: string;
  displayName?: string;
  authProvider?: AuthProvider | string | null;
  network?: string;

  private static readonly logger = new Logger(AuthPayloadValidator.name);

  static validate(payload: any): void {
    if (!payload) {
      throw new BadRequestException('Payload is required');
    }

    if (payload.authProvider !== undefined && payload.authProvider !== null) {
      if (typeof payload.authProvider !== 'string') {
        throw new BadRequestException('authProvider must be a string');
      }

      if (payload.authProvider.trim() === '') {
        throw new BadRequestException('authProvider cannot be empty');
      }

      if (!isValidAuthProvider(payload.authProvider)) {
        const validNames = getValidProviderNames().join(', ');
        throw new BadRequestException(
          `authProvider must be one of: ${validNames}`,
        );
      }
    }
  }
}

@Injectable()
export class AuthOrchestratorService {
  private static readonly MAX_LOGGED_PROVIDER_LENGTH = 64;

  private readonly logger = new Logger(AuthOrchestratorService.name);

  validatePayload(payload: AuthPayloadValidator): boolean {
    if (!payload.authId) {
      this.logger.warn('Missing authId in payload');
      return false;
    }

    try {
      AuthPayloadValidator.validate(payload);
      return true;
    } catch (error) {
      this.logger.warn('Invalid authProvider', {
        providerType: typeof payload.authProvider,
        providerPreview: this.describeProvider(payload.authProvider),
        error: (error as Error).message,
      });
      return false;
    }
  }

  /**
   * Builds a bounded, non-sensitive description of the offending provider
   * value. Never returns the raw value and never touches other payload fields.
   */
  private describeProvider(value: unknown): string {
    if (typeof value !== 'string') {
      return `<${typeof value}>`;
    }

    const truncated = value.slice(0, AuthOrchestratorService.MAX_LOGGED_PROVIDER_LENGTH);
    return value.length > AuthOrchestratorService.MAX_LOGGED_PROVIDER_LENGTH
      ? `${truncated}…`
      : truncated;
  }
}
